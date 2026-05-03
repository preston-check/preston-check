#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-536
name: FFIEC Business Continuity Management
description: Verifies business continuity / disaster recovery documentation aligned with the FFIEC Business Continuity Management booklet. Required content includes BIA, recovery strategies, plan testing, and event management.
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
frameworks: FFIEC-BCM:2019, ISO-22301:2019, NIST-CSF:2.0:RC.RP
false_positive_rate: high
performance_class: fast
origin: FFIEC Business Continuity Management booklet (2019 update).
PRESTON_META

echo "P-536: FFIEC Business Continuity"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "FFIEC[_-]BCM|business[_-]continuity[_-]plan|BIA|business[_-]impact[_-]analysis|recovery[_-]strategy|BCM[_-]testing" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-536 FFIEC BCM" "$(echo "$hits" | wc -l | tr -d ' ') BCM reference(s)" \
  || record "WARN" "P-536 FFIEC BCM" "No FFIEC business-continuity documentation found"
