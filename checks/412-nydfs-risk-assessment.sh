#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-412
name: NYDFS Part 500 Annual Risk Assessment
description: Verifies an annual cybersecurity risk assessment per 23 NYCRR 500.09 — periodic written assessment that informs the cybersecurity program design and informs subsequent control prioritization.
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
frameworks: NYDFS:23NYCRR500:500.09, NIST-CSF:2.0:ID.RA, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: NYDFS Part 500.09 — annual risk assessment requirement.
PRESTON_META

echo "P-412: NYDFS Annual Risk Assessment"

SRC="${SOURCE_DIR:-.}"
ra=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "risk[_-]assessment[_-](annual|yearly)|annual[_-]risk[_-]assessment|cybersecurity[_-]risk[_-]assessment|500\.09" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$ra" ]] && record "PASS" "P-412 NYDFS risk assessment" "$(echo "$ra" | wc -l | tr -d ' ') risk assessment reference(s)" \
  || record "WARN" "P-412 NYDFS risk assessment" "No annual risk assessment documentation found"
