#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-444
name: MAS TRM Cybersecurity Incident Management
description: Verifies cybersecurity incident management per MAS TRM Section 8 — formal incident response process, reporting timelines (1-hour notification for severity 1 incidents), post-incident review.
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
frameworks: MAS-TRM:2021:Sec8, NIST-CSF:2.0:RS.CO, ISO-27001:2022:5.24
false_positive_rate: high
performance_class: fast
origin: MAS TRM Section 8 — incident management with 1-hour reporting requirement for severe incidents.
PRESTON_META

echo "P-444: MAS Cybersecurity Incident Management"

SRC="${SOURCE_DIR:-.}"
ir=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "incident[_-]response[_-]plan|IR[_-]plan|post[_-]incident[_-]review|MAS[_-]incident|1[_-]hour[_-]notification" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$ir" ]] && record "PASS" "P-444 MAS incident mgmt" "$(echo "$ir" | wc -l | tr -d ' ') IR documentation reference(s)" \
  || record "WARN" "P-444 MAS incident mgmt" "No IR plan / post-incident review documentation found"
