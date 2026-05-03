#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-434
name: OWASP LLM05 — Improper Output Handling
description: Detects LLM-generated output rendered as HTML, executed as code, or interpolated into SQL/shell without escaping. LLM completions are user-controlled by definition (via prompt injection); treating them as trusted leads to XSS, RCE, or SQL injection.
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
frameworks: OWASP-LLM-Top-10:2025:LLM05, OWASP-Top-10:2021:A03, CWE:79, CWE:94
false_positive_rate: medium
performance_class: fast
origin: OWASP LLM Top 10 (2025) LLM05 — Improper Output Handling.
PRESTON_META

echo "P-434: LLM Output Handling"

SRC="${SOURCE_DIR:-.}"
unsafe=$(grep -rn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" \
  -iE "dangerouslySetInnerHTML.*completion|innerHTML\s*=\s*[^=]*completion|eval\s*\(\s*[^)]*completion|exec\s*\(\s*[^)]*response.*choice|render_template_string.*completion" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$unsafe" ]] && record "FAIL" "P-434 LLM output handling" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe LLM output rendering / eval pattern(s)" \
  || record "PASS" "P-434 LLM output handling" "No unsafe LLM output handling patterns detected"
