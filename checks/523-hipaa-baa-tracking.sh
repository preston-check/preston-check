#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-523
name: HIPAA Business Associate Agreement (BAA) Tracking
description: Verifies BAA tracking documentation. HIPAA 164.314(a) requires Business Associate Agreements with every vendor that handles PHI, with documented terms and breach notification clauses.
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
frameworks: HIPAA:Security-Rule:164.314.a, NIST-CSF:2.0:GV.SC, ISO-27001:2022:5.19
false_positive_rate: high
performance_class: fast
origin: HIPAA BAA requirement (164.314(a)) — material audit finding.
PRESTON_META

echo "P-523: HIPAA BAA Tracking"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.json" --include="*.yml" \
  -iE "business[_-]associate[_-]agreement|\bBAA\b|HIPAA[_-]vendor|vendor[_-]PHI|BAA[_-]tracker|baa[_-]register" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-523 HIPAA BAA tracking" "$(echo "$hits" | wc -l | tr -d ' ') BAA reference(s)" \
  || record "WARN" "P-523 HIPAA BAA tracking" "No Business Associate Agreement tracking found"
