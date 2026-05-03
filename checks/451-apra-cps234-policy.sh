#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-451
name: APRA CPS 234 Information Security Policy Framework
description: Verifies the existence of an information security policy framework per APRA CPS 234 paragraphs 14-15 — board-approved policy that defines roles, responsibilities, and the controls applied to information assets.
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
frameworks: APRA-CPS234:2019:para14, ISO-27001:2022:5.1, NIST-CSF:2.0:GV.PO
false_positive_rate: high
performance_class: fast
origin: APRA CPS 234 paragraphs 14-15 — Information Security Policy Framework requirement.
PRESTON_META

echo "P-451: APRA CPS 234 Policy Framework"

SRC="${SOURCE_DIR:-.}"
pol=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "information[_-]security[_-]policy|board[_-]approved[_-]policy|policy[_-]framework|infosec[_-]policy" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$pol" ]] && record "PASS" "P-451 CPS 234 policy" "$(echo "$pol" | wc -l | tr -d ' ') policy reference(s)" \
  || record "WARN" "P-451 CPS 234 policy" "No information security policy framework documented"
