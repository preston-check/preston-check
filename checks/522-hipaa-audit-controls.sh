#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-522
name: HIPAA Audit Controls and Activity Logging
description: Verifies that activity logging of ePHI access events is documented per HIPAA 164.312(b). Audit controls must record and examine activity in information systems containing ePHI.
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
frameworks: HIPAA:Security-Rule:164.312.b, NIST-CSF:2.0:PR.PT, CIS-v8:8.5
false_positive_rate: high
performance_class: fast
origin: HIPAA Security Rule audit controls (164.312(b)).
PRESTON_META

echo "P-522: HIPAA Audit Controls"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" --include="*.yml" \
  -iE "ePHI[_-]audit|audit[_-]log[_-]ePHI|HIPAA[_-]audit|access[_-]event[_-]log|ePHI[_-]activity" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-522 HIPAA audit controls" "$(echo "$hits" | wc -l | tr -d ' ') HIPAA audit reference(s)" \
  || record "WARN" "P-522 HIPAA audit controls" "No HIPAA audit-control documentation found"
