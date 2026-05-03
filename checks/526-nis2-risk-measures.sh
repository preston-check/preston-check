#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-526
name: NIS2 Cybersecurity Risk Management Measures
description: Verifies documentation of NIS2 Article 21 cybersecurity risk-management measures (10 minimum measures including policies, incident handling, business continuity, supply chain security, training, encryption, and zero trust).
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIS2:2022/2555:Art.21, ISO-27001:2022:5.1, NIST-CSF:2.0:GV.RM
false_positive_rate: high
performance_class: fast
origin: NIS2 Article 21 mandatory measures.
PRESTON_META

echo "P-526: NIS2 Risk Management Measures"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" \
  -iE "NIS2[_-]measures|cybersecurity[_-]risk[_-]management|art\.?\s*21|10[_-]measures|zero[_-]trust[_-]architecture" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-526 NIS2 measures" "$(echo "$hits" | wc -l | tr -d ' ') NIS2 risk-management reference(s)" \
  || record "WARN" "P-526 NIS2 measures" "No NIS2 risk-management measures documentation found"
