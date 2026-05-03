#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-430
name: OWASP LLM01 — Prompt Injection
description: Detects direct concatenation of user-controlled input into LLM prompts without delimiters, role-tagging, or input sanitization. User strings concatenated into system prompts allow attackers to override instructions and exfiltrate or manipulate downstream behavior.
category: code-scan
severity: high
languages: typescript, javascript, python, java, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-LLM-Top-10:2025:LLM01, NIST-CSF:2.0:PR.DS, OWASP-API:2023:API3
false_positive_rate: high
performance_class: fast
origin: OWASP Top 10 for LLM Applications (2025) LLM01 — top vulnerability category for LLM-based applications.
PRESTON_META

echo "P-430: LLM Prompt Injection"

SRC="${SOURCE_DIR:-.}"
llm_use=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" \
  -iE "openai|anthropic|@anthropic-ai|bedrock|vertex.*ai|together.ai|@ai-sdk|huggingface|replicate|cohere\.|generateContent" "$SRC" 2>/dev/null \
  | grep -vE "/test/|node_modules" || true)

if [[ -z "$llm_use" ]]; then
  record "SKIP" "P-430 LLM prompt injection" "No LLM SDK references detected"
  return 0 2>/dev/null || true
fi

# Detect prompt construction patterns that include user input directly
unsafe=$(grep -rn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" \
  -E "system.*prompt.*\+.*req\.|prompt:\s*[\"'].*\\\$\{user|f\".*\\\{user_|f\".*\\\{request\.|String\.format[^)]*system[^)]*\\+\\s*user" "$SRC" 2>/dev/null \
  | grep -vE "/test/|node_modules" || true)

defense=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" \
  -iE "promptShield|llm-guard|guardrails|nvidia.*nemo.*guard|inputModeration|llm[_-]firewall|jailbreak[_-]detect|promptDefender|sanitize[_-]prompt" "$SRC" 2>/dev/null \
  | grep -vE "/test/|node_modules" || true)

if [[ -n "$unsafe" && -z "$defense" ]]; then
  record "FAIL" "P-430 LLM prompt injection" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe prompt-construction pattern(s) and no prompt-defense library"
elif [[ -n "$defense" ]]; then
  record "PASS" "P-430 LLM prompt injection" "$(echo "$defense" | wc -l | tr -d ' ') prompt-defense reference(s)"
else
  record "WARN" "P-430 LLM prompt injection" "LLM usage without observable prompt-injection defenses" "$(echo "$defense" | head -10)"
fi
