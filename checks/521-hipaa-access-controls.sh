#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-521
name: HIPAA Access Control Documentation
description: Verifies presence of HIPAA-required access control policy documentation (unique user IDs, automatic logoff, encryption/decryption procedures, audit controls). HIPAA 164.312(a)(1) and (b).
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
frameworks: HIPAA:Security-Rule:164.312.a, ISO-27001:2022:5.15
false_positive_rate: high
performance_class: fast
origin: HIPAA Security Rule access control safeguards.
PRESTON_META

echo "P-521: HIPAA Access Control Documentation"

SRC="${SOURCE_DIR:-.}"
hits=$(grep -rln --include="*.md" --include="*.txt" --include="*.pdf" --include="*.docx" \
  -iE "HIPAA|access[_-]control[_-]policy|ePHI|automatic[_-]logoff|unique[_-]user[_-]id|encryption[_-]decryption" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$hits" ]] && record "PASS" "P-521 HIPAA access controls" "$(echo "$hits" | wc -l | tr -d ' ') HIPAA reference(s)" \
  || record "WARN" "P-521 HIPAA access controls" "No HIPAA access-control documentation found"
