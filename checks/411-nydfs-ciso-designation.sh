#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-411
name: NYDFS Part 500 CISO Designation
description: Verifies designation of a qualified Chief Information Security Officer per 23 NYCRR 500.04. The 2023 amendments require CISO independence and an annual written report to the senior governing body.
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
frameworks: NYDFS:23NYCRR500:500.04, NIST-CSF:2.0:GV.RR, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: NYDFS Part 500.04 — CISO designation and annual report requirement.
PRESTON_META

echo "P-411: NYDFS CISO Designation"

SRC="${SOURCE_DIR:-.}"
ciso=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" \
  -iE "CISO|chief[_-]information[_-]security[_-]officer|ciso[_-]annual[_-]report|500\.04" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$ciso" ]] && record "PASS" "P-411 NYDFS CISO" "$(echo "$ciso" | wc -l | tr -d ' ') CISO reference(s)" \
  || record "WARN" "P-411 NYDFS CISO" "No CISO designation evidence found"
