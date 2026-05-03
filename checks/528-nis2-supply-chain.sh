#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-528
name: NIS2 Supply Chain Security
description: Verifies NIS2 supply chain security measures — direct supplier risk, ICT product/service vulnerabilities, supplier development practices per NIS2 Article 21(2)(d).
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
frameworks: NIS2:2022/2555:Art.21.2.d, NIST-CSF:2.0:GV.SC
false_positive_rate: high
performance_class: fast
origin: NIS2 supply chain security mandate.
PRESTON_META

echo "P-528: NIS2 Supply Chain Security"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "NIS2[_-]supply[_-]chain|supplier[_-]risk[_-]EU|ICT[_-]vendor[_-]security|supply[_-]chain[_-]measures" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-528 NIS2 supply chain" "$(echo "$hits" | wc -l | tr -d ' ') NIS2 supply-chain reference(s)" \
  || record "WARN" "P-528 NIS2 supply chain" "No NIS2 supply-chain security documentation found"
