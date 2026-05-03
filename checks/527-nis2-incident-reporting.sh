#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-527
name: NIS2 24-Hour Incident Reporting
description: Verifies NIS2-aligned incident reporting capability — 24-hour early warning, 72-hour notification, 1-month final report per NIS2 Article 23. Significant incidents must be reported to CSIRTs.
category: compliance-evidence
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIS2:2022/2555:Art.23, NIST-CSF:2.0:RS.CO
false_positive_rate: high
performance_class: fast
origin: NIS2 Article 23 incident reporting timeline.
PRESTON_META

echo "P-527: NIS2 24-Hour Incident Reporting"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "NIS2[_-]incident|24[_-]hour[_-]warning|72[_-]hour[_-]notification|CSIRT|significant[_-]incident|art\.?\s*23" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-527 NIS2 incident reporting" "$(echo "$hits" | wc -l | tr -d ' ') NIS2 incident-reporting reference(s)" \
  || record "WARN" "P-527 NIS2 incident reporting" "No NIS2 24h/72h incident reporting documentation found"
