#!/bin/bash
###############################################################################
# lib/ai_analyze.sh — AI-augmented finding analysis
#
# Sends individual FAIL/WARN findings to an LLM (Anthropic Claude or OpenAI)
# for false-positive classification, plain-English explanation, and a
# concrete fix suggestion. Output is appended to the addendum section of
# the report alongside the raw findings.
#
# This is a moat-building feature: the more scans run with AI augmentation,
# the more we accumulate (privately, server-side) data on which check
# patterns generate false positives, which fix suggestions get accepted by
# users, and which findings ship to production. That feedback loop is what
# makes Preston-Check's AI layer get sharper than competitors over time.
#
# Activation:
#   - Set ANTHROPIC_API_KEY or OPENAI_API_KEY in env
#   - Pass --ai-augment to the runner (or set PRESTON_AI=1)
#   - Disabled in --airgap mode unconditionally
#
# Privacy:
#   - Sends finding context (file:line:content + ~10 surrounding lines)
#   - Does NOT send the entire codebase
#   - The user controls activation; default is OFF
#   - Free tier: 50 calls/scan rate-limited; Pro/Enterprise: unlimited
###############################################################################

AI_PROVIDER="${PRESTON_AI_PROVIDER:-anthropic}"
AI_MODEL_ANTHROPIC="${PRESTON_AI_MODEL_ANTHROPIC:-claude-haiku-4-5}"
AI_MODEL_OPENAI="${PRESTON_AI_MODEL_OPENAI:-gpt-4o-mini}"
AI_CACHE_DIR="${PRESTON_AI_CACHE:-${HOME}/.preston-check/ai-cache}"
AI_MAX_CALLS_FREE=50

mkdir -p "$AI_CACHE_DIR" 2>/dev/null

ai_is_available() {
  if [[ "${AIRGAP_MODE:-false}" == "true" ]]; then return 1; fi
  if [[ "${PRESTON_AI:-false}" != "true" && "${AI_AUGMENT:-false}" != "true" ]]; then return 1; fi
  if ! command -v curl >/dev/null 2>&1; then return 1; fi
  case "$AI_PROVIDER" in
    anthropic) [[ -n "${ANTHROPIC_API_KEY:-}" ]] || return 1 ;;
    openai)    [[ -n "${OPENAI_API_KEY:-}" ]] || return 1 ;;
    ollama)    command -v ollama >/dev/null || return 1 ;;
  esac
  return 0
}

# Hash a finding for cache lookup. Same finding → same cache hit.
ai_finding_hash() {
  local check="$1" finding="$2"
  if command -v shasum >/dev/null 2>&1; then
    printf '%s|%s' "$check" "$finding" | shasum -a 256 | cut -d' ' -f1
  else
    printf '%s|%s' "$check" "$finding" | sha256sum | cut -d' ' -f1
  fi
}

# Extract surrounding code context for a finding (file:line:content)
ai_get_context() {
  local finding_line="$1"
  local file line context
  file="$(echo "$finding_line" | cut -d: -f1)"
  line="$(echo "$finding_line" | cut -d: -f2)"
  if [[ -f "$file" && "$line" =~ ^[0-9]+$ ]]; then
    local start=$((line - 5))
    local end=$((line + 5))
    [[ $start -lt 1 ]] && start=1
    sed -n "${start},${end}p" "$file" 2>/dev/null
  fi
}

# Build the analysis prompt
ai_build_prompt() {
  local check_id="$1" check_name="$2" finding="$3" context="$4" severity="$5" frameworks="$6"
  cat <<PROMPT
You are a senior fintech security engineer analyzing a static-analysis finding.

Check: $check_id $check_name
Severity: $severity
Frameworks: $frameworks

Finding (file:line:content):
$finding

Surrounding code context:
\`\`\`
$context
\`\`\`

Analyze this finding and respond with JSON only:
{
  "classification": "real" | "likely-false-positive" | "needs-review",
  "confidence": 0.0-1.0,
  "explanation": "1-2 sentences in plain English",
  "fix_suggestion": "concrete code change or 'manual review required'",
  "framework_relevance": "which framework controls this most affects",
  "real_world_incidents": "1 sentence citing similar real fintech incident, or 'none'"
}
PROMPT
}

# Call Anthropic Claude API
ai_call_anthropic() {
  local prompt="$1"
  local payload
  payload=$(jq -n --arg model "$AI_MODEL_ANTHROPIC" --arg prompt "$prompt" '{
    model: $model,
    max_tokens: 1024,
    messages: [{role: "user", content: $prompt}]
  }')
  curl -s -m 30 -X POST https://api.anthropic.com/v1/messages \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d "$payload" 2>/dev/null \
    | jq -r '.content[0].text // empty' 2>/dev/null
}

# Call OpenAI API
ai_call_openai() {
  local prompt="$1"
  local payload
  payload=$(jq -n --arg model "$AI_MODEL_OPENAI" --arg prompt "$prompt" '{
    model: $model,
    response_format: {type: "json_object"},
    messages: [{role: "user", content: $prompt}]
  }')
  curl -s -m 30 -X POST https://api.openai.com/v1/chat/completions \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null \
    | jq -r '.choices[0].message.content // empty' 2>/dev/null
}

# Call local Ollama (offline / airgap-friendly when paired with --no-airgap)
ai_call_ollama() {
  local prompt="$1"
  curl -s -m 60 -X POST http://localhost:11434/api/generate \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg model "${PRESTON_AI_MODEL_OLLAMA:-llama3.1:8b}" --arg prompt "$prompt" '{
      model: $model, prompt: $prompt, stream: false, format: "json"
    }')" 2>/dev/null | jq -r '.response // empty' 2>/dev/null
}

# Main entry: take a finding, return JSON analysis (cached)
ai_analyze_finding() {
  local check_id="$1" check_name="$2" finding="$3" severity="$4" frameworks="$5"
  ai_is_available || { echo ""; return 1; }
  command -v jq >/dev/null 2>&1 || { echo ""; return 1; }

  local hash cache_file
  hash=$(ai_finding_hash "$check_id" "$finding")
  cache_file="$AI_CACHE_DIR/${hash}.json"
  if [[ -f "$cache_file" ]]; then
    cat "$cache_file"
    return 0
  fi

  local context prompt response
  context=$(ai_get_context "$finding")
  prompt=$(ai_build_prompt "$check_id" "$check_name" "$finding" "$context" "$severity" "$frameworks")

  case "$AI_PROVIDER" in
    anthropic) response=$(ai_call_anthropic "$prompt") ;;
    openai)    response=$(ai_call_openai "$prompt") ;;
    ollama)    response=$(ai_call_ollama "$prompt") ;;
    *)         response="" ;;
  esac

  if [[ -n "$response" ]]; then
    echo "$response" > "$cache_file"
    echo "$response"
  fi
}

# Format an analysis JSON object as a markdown block for the report addendum
ai_format_analysis() {
  local json="$1"
  [[ -z "$json" ]] && return 0
  local classification confidence explanation fix relevance incidents
  classification=$(echo "$json" | jq -r '.classification // "unknown"' 2>/dev/null)
  confidence=$(echo "$json" | jq -r '.confidence // 0' 2>/dev/null)
  explanation=$(echo "$json" | jq -r '.explanation // ""' 2>/dev/null)
  fix=$(echo "$json" | jq -r '.fix_suggestion // ""' 2>/dev/null)
  relevance=$(echo "$json" | jq -r '.framework_relevance // ""' 2>/dev/null)
  incidents=$(echo "$json" | jq -r '.real_world_incidents // ""' 2>/dev/null)

  cat <<MARKDOWN
**AI assessment:** \`$classification\` (confidence: $confidence)

$explanation

**Suggested fix:** $fix

**Framework relevance:** $relevance

**Related incidents:** $incidents

MARKDOWN
}

export -f ai_is_available ai_analyze_finding ai_format_analysis
