#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-539
name: FFIEC Development and Acquisition
description: Verifies SDLC and acquisition-process documentation aligned with the FFIEC Development & Acquisition booklet. Covers project management, risk management, and quality control across the IT lifecycle.
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
frameworks: FFIEC-DA:2004, ISO-27001:2022:8.25, NIST-SSDF:1.1
false_positive_rate: high
performance_class: fast
origin: FFIEC Development and Acquisition booklet.
PRESTON_META

echo "P-539: FFIEC Development & Acquisition"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "FFIEC[_-]development|SDLC[_-]bank|software[_-]acquisition|project[_-]management[_-]bank|FFIEC[_-]DA" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-539 FFIEC dev/acq" "$(echo "$hits" | wc -l | tr -d ' ') reference(s)" \
  || record "WARN" "P-539 FFIEC dev/acq" "No FFIEC development/acquisition documentation found"
