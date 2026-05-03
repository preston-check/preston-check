#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-407
name: DORA Critical Function ICT Continuity (RTO/RPO)
description: Verifies that critical-or-important business functions have explicit RTO (Recovery Time Objective) and RPO (Recovery Point Objective) targets documented and tested. DORA Article 11 (ICT business continuity) requires defined targets for recovery of critical functions.
category: compliance-evidence
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.2.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: DORA:2025:Art.11, DORA:2025:Art.12, NIST-CSF:2.0:RC.RP, ISO-27001:2022:5.30, ISO-22301:2019
false_positive_rate: medium
performance_class: fast
origin: DORA Articles 11-12 require ICT business continuity policies with explicit recovery objectives for critical functions; ISO 22301 is the canonical reference.
PRESTON_META

echo "P-407: DORA Critical Function Continuity"

SRC="${SOURCE_DIR:-.}"

bcp=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" --include="*.json" \
  -iE 'RTO|recovery[_-]time[_-]objective|RPO|recovery[_-]point[_-]objective|critical[_-]function[_-]continuity|business[_-]impact[_-]analysis|BIA' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

dr_docs=$(grep -rln --include="*.md" --include="*.txt" \
  -iE 'disaster[_-]recovery|business[_-]continuity|continuity[_-]plan' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

if [[ -n "$bcp" ]]; then
  count=$(echo "$bcp" | wc -l | tr -d ' ')
  record "PASS" "P-407 DORA critical function continuity" "$count reference(s) to RTO/RPO/BIA"
elif [[ -n "$dr_docs" ]]; then
  record "WARN" "P-407 DORA critical function continuity" "Generic DR/BCP references; DORA Art. 11 requires explicit RTO/RPO per critical function"
else
  record "FAIL" "P-407 DORA critical function continuity" "No BCP/DR documentation with RTO/RPO targets found"
fi
