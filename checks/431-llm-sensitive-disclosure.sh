#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-431
name: OWASP LLM02 — Sensitive Information Disclosure
description: Detects PII or secrets being passed into LLM prompts, or LLM responses being logged with PII intact. Prompts and completions often pass through third-party providers, log aggregators, and observability tools — every link in that chain is a disclosure surface.
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
frameworks: OWASP-LLM-Top-10:2025:LLM02, NIST-CSF:2.0:PR.DS, GDPR:2018
false_positive_rate: high
performance_class: fast
origin: OWASP Top 10 for LLM Applications (2025) LLM02. Has driven multiple regulatory enforcement actions for PII routed through ChatGPT and similar.
PRESTON_META

echo "P-431: LLM Sensitive Information Disclosure"

SRC="${SOURCE_DIR:-.}"
llm_present=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" \
  -iE "openai|anthropic|bedrock|vertex.*ai" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -z "$llm_present" ]] && { record "SKIP" "P-431 LLM PII disclosure" "No LLM usage detected"; return 0 2>/dev/null || true; }

redaction=$(grep -rln --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" \
  -iE "redact|maskPII|piiScrubber|presidio|microsoft[_-]presidio|scrub[_-]pii|piiFilter" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$redaction" ]] && record "PASS" "P-431 LLM PII disclosure" "$(echo "$redaction" | wc -l | tr -d ' ') PII redaction reference(s)" \
  || record "WARN" "P-431 LLM PII disclosure" "LLM usage without PII redaction (Presidio, custom scrubber)"
