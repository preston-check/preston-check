#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-450
name: APRA CPS 234 Information Security Capability
description: Verifies documented information security capability commensurate with the size and complexity of operations per APRA CPS 234 paragraph 13. Required for APRA-regulated entities (banks, insurers, super funds).
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
frameworks: APRA-CPS234:2019:para13, NIST-CSF:2.0:GV.RM, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: Australian Prudential Regulation Authority (APRA) Prudential Standard CPS 234, effective July 2019.
PRESTON_META

echo "P-450: APRA CPS 234 Information Security Capability"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "APRA|CPS[_-]234|prudential[_-]standard|information[_-]security[_-]capability|APRA[_-]regulated" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-450 APRA CPS 234 capability" "$(echo "$hits" | wc -l | tr -d ' ') APRA / CPS 234 reference(s)" \
  || record "WARN" "P-450 APRA CPS 234 capability" "No APRA CPS 234 documentation found"
