#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-319
name: Key Rotation Schedule
description: Verifies the existence of automated or documented key rotation policies. Long-lived signing keys accumulate exposure: every developer who has ever had access, every backup that ever held them, and every memory dump that captured them remain a risk surface forever.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, ISO-27001:2022:A.10.1, PCI-DSS:4.0:3.6
cwe: 798
false_positive_rate: high
performance_class: fast
origin: NIST 800-57 and PCI-DSS both specify cryptoperiods; absence of rotation procedures is a recurring audit finding for crypto custodians.
PRESTON_META

echo "P-319: Key Rotation Schedule"

SRC="${SOURCE_DIR:-.}"

rot_refs=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" --include="*.json" --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'key[_-]rotation|rotateKeys|cryptoperiod|key[_-]lifetime|rotation[_-]schedule|rotateSigning|rotation[_-]policy|kms.*rotation|EnableKeyRotation' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

if [[ -n "$rot_refs" ]]; then
  count=$(echo "$rot_refs" | wc -l | tr -d ' ')
  record "PASS" "P-319 Key rotation" "$count reference(s) to key rotation policy or schedule"
else
  record "WARN" "P-319 Key rotation" "No key-rotation references found; document a rotation policy or enable automated KMS rotation" "$(echo "$rot_refs" | head -10)"
fi
