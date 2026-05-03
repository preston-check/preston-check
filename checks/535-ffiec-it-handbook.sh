#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-535
name: FFIEC IT Handbook Adoption
description: Verifies adoption of the FFIEC IT Examination Handbook framework. The FFIEC IT Handbook is the de facto US banking IT-risk framework covering Audit, Business Continuity, Information Security, Operations, Development & Acquisition, Outsourcing, Management, Wholesale Payments, and Retail Payments.
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
frameworks: FFIEC-ITH:2024, NIST-CSF:2.0:GV.OC
false_positive_rate: high
performance_class: fast
origin: FFIEC IT Examination Handbook — material standard for US banks and many fintech bank-partnership programs.
PRESTON_META

echo "P-535: FFIEC IT Handbook"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "FFIEC|FFIEC[_-]IT[_-]Handbook|FFIEC[_-]CAT|cybersecurity[_-]assessment[_-]tool" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-535 FFIEC handbook" "$(echo "$hits" | wc -l | tr -d ' ') FFIEC reference(s)" \
  || record "WARN" "P-535 FFIEC handbook" "No FFIEC IT Handbook references found"
