#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-432
name: OWASP LLM03 — Supply Chain Vulnerabilities
description: Detects LLM supply chain risks — unpinned model versions, untrusted model sources, missing model card or provenance verification. A model swap by a compromised upstream is a wholesale takeover of LLM-driven business logic.
category: code-scan
severity: medium
languages: typescript, javascript, python, java, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-LLM-Top-10:2025:LLM03, NIST-CSF:2.0:GV.SC
false_positive_rate: high
performance_class: fast
origin: OWASP LLM Top 10 (2025) LLM03 — Supply Chain.
PRESTON_META

echo "P-432: LLM Supply Chain"

SRC="${SOURCE_DIR:-.}"
unpinned=$(grep -rn --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rs" \
  -iE "model:\s*[\"'](gpt|claude|gemini|llama).*latest|model_name\s*=\s*[\"'](gpt|claude).*-latest|model:\s*[\"']mistralai/[^\"']+:latest" "$SRC" 2>/dev/null | grep -v node_modules | head -5 || true)
[[ -n "$unpinned" ]] && record "WARN" "P-432 LLM supply chain" "$(echo "$unpinned" | wc -l | tr -d ' ') unpinned model reference(s) using -latest tags" \
  || record "PASS" "P-432 LLM supply chain" "No unpinned -latest LLM model references"
