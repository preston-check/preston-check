#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-542
name: GLBA Notification Rule (30-day FTC report)
description: Verifies documented procedure for the GLBA Notification Rule — financial institutions must notify the FTC of security events affecting 500+ consumers within 30 days, effective May 2024.
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
frameworks: GLBA-Safeguards:16CFR314.5, NIST-CSF:2.0:RS.CO
false_positive_rate: high
performance_class: fast
origin: 16 CFR 314.5 — Notification Rule, effective May 2024. 30-day window for notice to FTC.
PRESTON_META

echo "P-542: GLBA Notification Rule"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "GLBA[_-]notification|FTC[_-]breach[_-]notice|30[_-]day[_-]FTC|safeguards[_-]notification[_-]rule|314\.5" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-542 GLBA notification" "$(echo "$hits" | wc -l | tr -d ' ') notification reference(s)" \
  || record "WARN" "P-542 GLBA notification" "No GLBA Notification Rule documentation found"
