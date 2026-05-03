#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-524
name: HIPAA Breach Notification Procedure
description: Verifies documented breach notification procedure per HIPAA Breach Notification Rule (45 CFR 164.400-414). Covered entities and business associates must notify HHS, individuals, and (for breaches >500) media within 60 days.
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
frameworks: HIPAA:Breach-Notification:164.400-414, NIST-CSF:2.0:RS.CO
false_positive_rate: high
performance_class: fast
origin: HIPAA Breach Notification Rule — 60-day notification requirement.
PRESTON_META

echo "P-524: HIPAA Breach Notification"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "HIPAA[_-]breach|breach[_-]notification|HHS[_-]notification|60[_-]day[_-]notification|patient[_-]notification" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-524 HIPAA breach notification" "$(echo "$hits" | wc -l | tr -d ' ') breach-notification reference(s)" \
  || record "WARN" "P-524 HIPAA breach notification" "No HIPAA breach-notification procedure documentation found"
