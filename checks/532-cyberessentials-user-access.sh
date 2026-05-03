#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-532
name: Cyber Essentials User Access Control
description: Verifies user-access control documentation per UK Cyber Essentials Control 3. Unique user accounts, MFA, account-creation/removal procedures, principle of least privilege.
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
frameworks: UK-Cyber-Essentials:2024:Control-3, NIST-CSF:2.0:PR.AC, CIS-v8:5.1
false_positive_rate: high
performance_class: fast
origin: UK Cyber Essentials Control 3 — User Access Control.
PRESTON_META

echo "P-532: Cyber Essentials User Access"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "user[_-]access[_-]control|account[_-]creation[_-]procedure|joiner[_-]mover[_-]leaver|JML[_-]process|account[_-]review[_-]quarterly" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-532 CE user access" "$(echo "$hits" | wc -l | tr -d ' ') access-control reference(s)" \
  || record "WARN" "P-532 CE user access" "No Cyber Essentials user-access documentation found"
