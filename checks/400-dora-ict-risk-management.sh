#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-400
name: DORA ICT Risk Management Framework
description: Verifies presence of an ICT risk management framework documenting roles, responsibilities, risk identification, protection, detection, response, and recovery measures. DORA Article 6 mandates this for all in-scope EU financial entities.
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
frameworks: DORA:2025:Art.5, DORA:2025:Art.6, DORA:2025:Art.16, NIST-CSF:2.0:GV.RM, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: EU Digital Operational Resilience Act (Regulation 2022/2554) entered into force 17 January 2025; Articles 5-16 require a documented ICT risk-management framework. Top-priority compliance gap for all EU fintech buyers.
PRESTON_META

echo "P-400: DORA ICT Risk Management Framework"

SRC="${SOURCE_DIR:-.}"

# Look for ICT risk management documentation
docs=$(find "$SRC" -type f \( -iname "*.md" -o -iname "*.pdf" -o -iname "*.docx" \) 2>/dev/null \
  | xargs grep -lE -i "DORA|ICT risk management|ICT[_-]risk[_-]framework|operational[_-]resilience|Digital Operational Resilience" 2>/dev/null \
  | grep -vE 'node_modules' | head -10 || true)

template_dir="${SRC}/compliance-template"
[[ -d "$template_dir" ]] && template_refs=$(find "$template_dir" -iname "*dora*" -o -iname "*ict-risk*" 2>/dev/null) || template_refs=""

if [[ -n "$docs" || -n "$template_refs" ]]; then
  count=$([[ -n "$docs" ]] && echo "$docs" | wc -l | tr -d ' ' || echo 0)
  record "PASS" "P-400 DORA ICT risk framework" "$count documentation reference(s) to DORA / ICT risk management"
else
  record "WARN" "P-400 DORA ICT risk framework" "No DORA / ICT risk management framework documentation found"
fi
