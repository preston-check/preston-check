#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-404
name: DORA ICT Concentration Risk Assessment
description: Verifies documented assessment of concentration risk on ICT third parties — specifically dependency on a single cloud, payment processor, or CTPP. DORA Article 29 requires explicit treatment of how the entity would maintain critical functions if a major ICT provider became unavailable.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.2.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: DORA:2025:Art.29, NIST-CSF:2.0:GV.SC-7, ISO-27001:2022:5.19
false_positive_rate: high
performance_class: fast
origin: DORA Article 29 explicitly addresses concentration risk; ESMA and EBA jointly designate Critical Third-Party Providers (CTPPs) — failure to assess concentration risk on these providers is a recurring audit finding.
PRESTON_META

echo "P-404: DORA Concentration Risk"

SRC="${SOURCE_DIR:-.}"

conc=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" --include="*.json" \
  -iE 'concentration[_-]risk|single[_-]point[_-]dependency|CTPP[_-]dependency|cloud[_-]concentration|vendor[_-]concentration|exit[_-]plan[_-]cloud|fallback[_-]cloud[_-]provider' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

if [[ -n "$conc" ]]; then
  count=$(echo "$conc" | wc -l | tr -d ' ')
  record "PASS" "P-404 DORA concentration risk" "$count reference(s) to concentration-risk assessment"
else
  record "WARN" "P-404 DORA concentration risk" "No documented ICT concentration-risk assessment found"
fi
