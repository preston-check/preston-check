#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-410
name: NYDFS Part 500 Cybersecurity Program Documentation
description: Verifies a written cybersecurity program is documented per 23 NYCRR 500.02. Required of all NY-licensed financial institutions; absence is the most-cited NYDFS exam finding.
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
frameworks: NYDFS:23NYCRR500:500.02, NIST-CSF:2.0:GV.PO, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: NYDFS Part 500 (23 NYCRR 500), 2017 with major 2023 amendments. Material requirement for any US fintech with NY exposure.
PRESTON_META

echo "P-410: NYDFS Cybersecurity Program"

SRC="${SOURCE_DIR:-.}"
prog=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "NYDFS|23 NYCRR 500|cybersecurity[_-]program|Part 500|Section 500\.02" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$prog" ]] && record "PASS" "P-410 NYDFS program" "$(echo "$prog" | wc -l | tr -d ' ') reference(s) to NYDFS cybersecurity program" \
  || record "WARN" "P-410 NYDFS program" "No NYDFS cybersecurity program documentation found"
