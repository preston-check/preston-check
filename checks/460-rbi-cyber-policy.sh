#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-460
name: RBI Cyber Security Policy
description: Verifies presence of a board-approved Cyber Security Policy per RBI Cyber Security Framework (2016 + 2024 updates). Mandatory for Indian banks, NBFCs, and payment system operators.
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
frameworks: RBI-CSF:2024, NIST-CSF:2.0:GV.PO, ISO-27001:2022:5.1
false_positive_rate: high
performance_class: fast
origin: RBI Cyber Security Framework (DBS.CO.CSITE.BC.NO.11/33.01.001/2015-16) plus 2024 updates.
PRESTON_META

echo "P-460: RBI Cyber Security Policy"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "RBI[_-]cyber|reserve[_-]bank[_-]of[_-]india|RBI[_-]CSF|board[_-]approved.*cyber[_-]security|RBI[_-]circular" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-460 RBI cyber policy" "$(echo "$hits" | wc -l | tr -d ' ') RBI / cyber policy reference(s)" \
  || record "WARN" "P-460 RBI cyber policy" "No RBI cyber security policy documentation found"
