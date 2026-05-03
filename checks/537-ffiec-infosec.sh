#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-537
name: FFIEC Information Security Booklet
description: Verifies infosec-program documentation aligned with the FFIEC Information Security booklet. Includes governance, threat-monitoring, identity and access management, and ongoing security operations.
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
frameworks: FFIEC-ISB:2016, NIST-CSF:2.0:GV.RM, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: FFIEC Information Security booklet (2016 update).
PRESTON_META

echo "P-537: FFIEC Information Security"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "FFIEC[_-]ISB|FFIEC[_-]information[_-]security|infosec[_-]program|threat[_-]monitoring[_-]bank" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-537 FFIEC InfoSec" "$(echo "$hits" | wc -l | tr -d ' ') reference(s)" \
  || record "WARN" "P-537 FFIEC InfoSec" "No FFIEC information-security booklet documentation found"
