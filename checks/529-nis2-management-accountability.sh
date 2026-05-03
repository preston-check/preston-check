#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-529
name: NIS2 Management Body Accountability
description: Verifies documentation of management body responsibilities per NIS2 Article 20 — board approves cybersecurity risk-management measures, follows training, and is personally liable for non-compliance.
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
frameworks: NIS2:2022/2555:Art.20, NIST-CSF:2.0:GV.RR
false_positive_rate: high
performance_class: fast
origin: NIS2 Article 20 — management accountability with personal liability.
PRESTON_META

echo "P-529: NIS2 Management Body Accountability"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "management[_-]body[_-]NIS2|board[_-]cybersecurity|art\.?\s*20[_-]NIS2|management[_-]accountability|board[_-]training[_-]cyber" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-529 NIS2 management" "$(echo "$hits" | wc -l | tr -d ' ') management-body reference(s)" \
  || record "WARN" "P-529 NIS2 management" "No NIS2 management-accountability documentation found"
