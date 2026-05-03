#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-437
name: OWASP LLM10 — Unbounded Consumption
description: Detects LLM API usage without per-user rate limits, max-token budgets, or cost guardrails. An attacker that hits an unbounded LLM endpoint can drive cloud costs to bankruptcy in hours; this is the LLM-era equivalent of resource exhaustion.
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
frameworks: OWASP-LLM-Top-10:2025:LLM10, OWASP-API:2023:API4, CWE:400
false_positive_rate: medium
performance_class: fast
origin: OWASP LLM Top 10 (2025) LLM10 — Unbounded Consumption. Cost-based DoS is the new resource exhaustion.
PRESTON_META

echo "P-437: LLM Unbounded Consumption"

SRC="${SOURCE_DIR:-.}"
llm_present=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" \
  -iE "openai|anthropic|bedrock|generateContent|chat\.completions" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -z "$llm_present" ]] && { record "SKIP" "P-437 LLM unbounded consumption" "No LLM usage detected"; return 0 2>/dev/null || true; }

guards=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE "max_tokens|maxTokens|maxOutputTokens|tokenBudget|costGuard|llm[_-]rate[_-]limit|spending[_-]limit|usage[_-]quota|tokenLimitExceeded" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$guards" ]] && record "PASS" "P-437 LLM unbounded consumption" "$(echo "$guards" | wc -l | tr -d ' ') token/cost guard reference(s)" \
  || record "FAIL" "P-437 LLM unbounded consumption" "LLM usage without max_tokens / cost guard / per-user quota"
