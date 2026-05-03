#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-453
name: APRA CPS 234 Incident Management and Notification
description: Verifies incident response and APRA notification processes per CPS 234 paragraphs 32-34 — APRA must be notified within 72 hours of a material information security incident.
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
frameworks: APRA-CPS234:2019:para32, NIST-CSF:2.0:RS.CO
false_positive_rate: high
performance_class: fast
origin: APRA CPS 234 paragraphs 32-34 — 72-hour material incident notification.
PRESTON_META

echo "P-453: CPS 234 Incident Notification"

SRC="${SOURCE_DIR:-.}"
ir=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "APRA[_-]notification|72[_-]hour[_-]notification|incident[_-]response[_-]plan|material[_-]incident|CPS[_-]234[_-]reporting" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$ir" ]] && record "PASS" "P-453 CPS 234 incident notification" "$(echo "$ir" | wc -l | tr -d ' ') notification reference(s)" \
  || record "WARN" "P-453 CPS 234 incident notification" "No APRA notification or 72-hour incident process found"
