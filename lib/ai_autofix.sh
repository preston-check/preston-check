#!/bin/bash
###############################################################################
# lib/ai_autofix.sh — AI-augmented patch generation for findings
#
# Given a FAIL/WARN finding (file:line:content), this asks an LLM to produce
# a unified-diff patch that resolves the issue. The patch is included in the
# report addendum next to the AI analysis output (lib/ai_analyze.sh) so the
# developer sees both the diagnosis AND a one-click remediation.
#
# Why this matters (moat strategy):
#   Auto-fix is the #1 conversion lever from free → paid in the Snyk
#   playbook. Detection alone produces alert fatigue; detection + fix is
#   what makes developers personally love the tool. We ship fix
#   generation for every finding the AI is confident about, and we emit
#   the diff inline in the report so a developer can `git apply` it.
#
# Activation:
#   - --ai-fix flag on the runner, or PRESTON_AI_FIX=1
#   - Implicitly enables the AI subsystem (no need to also pass --ai-augment)
#   - Requires ANTHROPIC_API_KEY or OPENAI_API_KEY (or local Ollama)
#   - Disabled in --airgap mode unconditionally
#
# Privacy:
#   - Sends the same scoped context as ai_analyze.sh (file:line:content +
#     ~20 surrounding lines for fix generation, slightly more than analysis)
#   - Does NOT send the entire file or codebase
#   - Cached by finding hash so repeated runs over the same code don't
#     re-send to the LLM
###############################################################################

# Allow this file to be sourced after lib/ai_analyze.sh — we reuse its config.
AI_PROVIDER="${PRESTON_AI_PROVIDER:-anthropic}"
AI_MODEL_ANTHROPIC="${PRESTON_AI_MODEL_ANTHROPIC:-claude-haiku-4-5}"
AI_MODEL_OPENAI="${PRESTON_AI_MODEL_OPENAI:-gpt-4o-mini}"
AI_FIX_CACHE_DIR="${PRESTON_AI_CACHE:-${HOME}/.preston-check/ai-cache}/fixes"
mkdir -p "$AI_FIX_CACHE_DIR" 2>/dev/null

autofix_is_available() {
  if [[ "${AIRGAP_MODE:-false}" == "true" ]]; then return 1; fi
  if [[ "${AI_FIX:-false}" != "true" && "${PRESTON_AI_FIX:-false}" != "1" ]]; then return 1; fi
  if ! command -v curl >/dev/null 2>&1; then return 1; fi
  case "$AI_PROVIDER" in
    anthropic) [[ -n "${ANTHROPIC_API_KEY:-}" ]] || return 1 ;;
    openai)    [[ -n "${OPENAI_API_KEY:-}" ]] || return 1 ;;
    ollama)    command -v ollama >/dev/null || return 1 ;;
  esac
  return 0
}

# Wider context window for fix generation than for analysis — the model needs
# to understand more of the surrounding function to produce a working patch.
autofix_get_context() {
  local finding_line="$1"
  local file line
  file="$(echo "$finding_line" | cut -d: -f1)"
  line="$(echo "$finding_line" | cut -d: -f2)"
  if [[ -f "$file" && "$line" =~ ^[0-9]+$ ]]; then
    local start=$((line - 15))
    local end=$((line + 15))
    [[ $start -lt 1 ]] && start=1
    sed -n "${start},${end}p" "$file" 2>/dev/null
  fi
}

autofix_finding_hash() {
  local check="$1" finding="$2"
  if command -v shasum >/dev/null 2>&1; then
    printf 'fix|%s|%s' "$check" "$finding" | shasum -a 256 | cut -d' ' -f1
  else
    printf 'fix|%s|%s' "$check" "$finding" | sha256sum | cut -d' ' -f1
  fi
}

autofix_build_prompt() {
  local check_id="$1" check_name="$2" finding="$3" context="$4" severity="$5"
  local file line
  file="$(echo "$finding" | cut -d: -f1)"
  line="$(echo "$finding" | cut -d: -f2)"
  cat <<PROMPT
You are a senior fintech security engineer producing a minimal, correct patch
for a static-analysis finding. Output ONLY a unified diff (the kind \`git apply\`
accepts) — no commentary, no markdown fence, no explanation.

If you genuinely cannot produce a safe fix without more context, output the
single literal string:

    NO_AUTOFIX

Constraints:
- Modify ONLY $file. No other files.
- Keep the diff as small as possible. Do not refactor surrounding code.
- Preserve existing imports unless your fix requires a new one — then add it.
- Do not introduce new dependencies that aren't already in the project.
- The fix must address the security issue described, not paper over it.

Check: $check_id $check_name
Severity: $severity
Finding (file:line:content): $finding

Code context near $file:$line (15 lines before and after):
\`\`\`
$context
\`\`\`

Produce the unified diff now.
PROMPT
}

autofix_call_anthropic() {
  local prompt="$1"
  local payload
  payload=$(jq -n --arg model "$AI_MODEL_ANTHROPIC" --arg prompt "$prompt" '{
    model: $model,
    max_tokens: 1500,
    messages: [{role: "user", content: $prompt}]
  }')
  curl -s -m 45 -X POST https://api.anthropic.com/v1/messages \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d "$payload" 2>/dev/null \
    | jq -r '.content[0].text // empty' 2>/dev/null
}

autofix_call_openai() {
  local prompt="$1"
  local payload
  payload=$(jq -n --arg model "$AI_MODEL_OPENAI" --arg prompt "$prompt" '{
    model: $model,
    messages: [{role: "user", content: $prompt}]
  }')
  curl -s -m 45 -X POST https://api.openai.com/v1/chat/completions \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null \
    | jq -r '.choices[0].message.content // empty' 2>/dev/null
}

autofix_call_ollama() {
  local prompt="$1"
  curl -s -m 90 -X POST http://localhost:11434/api/generate \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg model "${PRESTON_AI_MODEL_OLLAMA:-llama3.1:8b}" --arg prompt "$prompt" '{
      model: $model, prompt: $prompt, stream: false
    }')" 2>/dev/null | jq -r '.response // empty' 2>/dev/null
}

# Validate that the response looks like a unified diff. Returns 0 if it does,
# 1 if it's NO_AUTOFIX or malformed.
autofix_is_diff() {
  local s="$1"
  [[ -z "$s" ]] && return 1
  [[ "$s" == "NO_AUTOFIX" ]] && return 1
  # Strip leading markdown code fences if the model wrapped the diff
  echo "$s" | grep -qE '^(diff --git|--- |\+\+\+ |@@ )' || return 1
  return 0
}

# Strip common LLM wrappers (markdown fences, leading prose) from the response
autofix_clean_diff() {
  local s="$1"
  # Remove ```diff or ``` openers and closers
  echo "$s" | awk '
    BEGIN { in_fence = 0 }
    /^```/ { in_fence = !in_fence; next }
    /^(diff --git|--- |\+\+\+ |@@ )/ { found = 1 }
    found { print }
  '
}

# Main entry. Echoes a unified-diff (or "" if no fix could be generated).
autofix_generate() {
  local check_id="$1" check_name="$2" finding="$3" severity="$4"
  autofix_is_available || { echo ""; return 1; }
  command -v jq >/dev/null 2>&1 || { echo ""; return 1; }

  local hash cache_file
  hash=$(autofix_finding_hash "$check_id" "$finding")
  cache_file="$AI_FIX_CACHE_DIR/${hash}.diff"
  if [[ -f "$cache_file" ]]; then
    cat "$cache_file"
    return 0
  fi

  local context prompt response cleaned
  context=$(autofix_get_context "$finding")
  [[ -z "$context" ]] && { echo ""; return 0; }
  prompt=$(autofix_build_prompt "$check_id" "$check_name" "$finding" "$context" "$severity")

  case "$AI_PROVIDER" in
    anthropic) response=$(autofix_call_anthropic "$prompt") ;;
    openai)    response=$(autofix_call_openai "$prompt") ;;
    ollama)    response=$(autofix_call_ollama "$prompt") ;;
    *)         response="" ;;
  esac

  cleaned=$(autofix_clean_diff "$response")
  if autofix_is_diff "$cleaned"; then
    printf '%s' "$cleaned" > "$cache_file"
    printf '%s' "$cleaned"
  else
    # Cache the negative result too so we don't re-ask for the same finding
    : > "$cache_file"
    echo ""
  fi
}

# Format an autofix patch for inclusion in the report addendum
autofix_format() {
  local diff="$1"
  [[ -z "$diff" ]] && return 0
  cat <<MARKDOWN
**Suggested patch** — review carefully before applying. To apply:
\`\`\`bash
preston-check report.md | sed -n '/^--- /,/^--- /p' | git apply --check
\`\`\`

\`\`\`diff
$diff
\`\`\`

MARKDOWN
}

export -f autofix_is_available autofix_generate autofix_format
