#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-443
name: MAS TRM System Security Testing
description: Verifies presence of pentest, vulnerability assessment, and source code review evidence per MAS TRM Section 13. Annual cadence for critical systems; results documented and remediation tracked.
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
frameworks: MAS-TRM:2021:Sec13, NIST-CSF:2.0:ID.RA-1, CIS-v8:18.1
false_positive_rate: high
performance_class: fast
origin: MAS TRM Section 13 — system security testing for critical systems.
PRESTON_META

echo "P-443: MAS System Security Testing"

SRC="${SOURCE_DIR:-.}"
ev=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "pentest|penetration[_-]test|VA[_-]VAPT|vulnerability[_-]assessment|source[_-]code[_-]review|MAS[_-]testing" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$ev" ]] && record "PASS" "P-443 MAS system testing" "$(echo "$ev" | wc -l | tr -d ' ') testing evidence reference(s)" \
  || record "WARN" "P-443 MAS system testing" "No pentest / VA / code review evidence found"
