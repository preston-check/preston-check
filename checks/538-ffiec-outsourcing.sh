#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-538
name: FFIEC Outsourcing Technology Services
description: Verifies third-party / outsourcing risk documentation aligned with the FFIEC Outsourcing Technology Services booklet. Includes due diligence, contract terms, oversight, and exit strategies.
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
frameworks: FFIEC-OTS:2004, NIST-CSF:2.0:GV.SC, ISO-27001:2022:5.19
false_positive_rate: high
performance_class: fast
origin: FFIEC Outsourcing Technology Services booklet.
PRESTON_META

echo "P-538: FFIEC Outsourcing"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "FFIEC[_-]outsourcing|technology[_-]services[_-]vendor|third[_-]party[_-]risk[_-]bank|critical[_-]vendor[_-]oversight" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-538 FFIEC outsourcing" "$(echo "$hits" | wc -l | tr -d ' ') reference(s)" \
  || record "WARN" "P-538 FFIEC outsourcing" "No FFIEC outsourcing documentation found"
