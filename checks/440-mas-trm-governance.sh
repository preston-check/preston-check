#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-440
name: MAS TRM Technology Risk Governance
description: Verifies presence of technology risk governance documentation per MAS Technology Risk Management Guidelines — board oversight of technology risk, technology risk management framework, periodic risk reporting.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: MAS-TRM:2021:TRG, NIST-CSF:2.0:GV.RM, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: Monetary Authority of Singapore Technology Risk Management Guidelines (revised 2021); standard for Singapore-licensed financial institutions and increasingly cited as APAC fintech benchmark.
PRESTON_META

echo "P-440: MAS TRM Technology Risk Governance"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" \
  -iE "MAS[_-]TRM|MAS technology risk|technology risk[_-]management|TRM[_-]framework|technology[_-]risk[_-]governance|MAS guidelines" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-440 MAS TRM governance" "$(echo "$hits" | wc -l | tr -d ' ') reference(s) to MAS TRM" \
  || record "WARN" "P-440 MAS TRM governance" "No MAS TRM governance documentation found"
