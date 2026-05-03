#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-36
name: Key Management
description: Checks key files in repo, rotation mechanisms.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:3.6, PCI-DSS:4.0:3.7, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-1, CIS-v8:3.11
PRESTON_META


# P-36: Encryption Key Management
echo "P-36: Key Management"
SRC="${SOURCE_DIR:-.}"

key_files=$(find "$SRC" -maxdepth 3 \( -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.jks" -o -name "*.keystore" \) \
  ! -path "*/target/*" ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" 2>/dev/null)
if [[ -z "$key_files" ]]; then
  record "PASS" "P-36 No key files in repo" "No private key/cert files in repository"
else
  count=$(echo "$key_files" | wc -l)
  record "FAIL" "P-36 Key files in repo" "$count key/cert files in repo (should be in Secrets Manager)"
fi

rotation=$(grep -rn --include="$SRC_EXT" --include="*.yml" \
  "key.*rotation\|rotate.*key\|key.*version\|rotateSecret\|key.*expir" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$rotation" ]]; then
  record "PASS" "P-36 Key rotation" "Key rotation mechanism found"
else
  record "WARN" "P-36 Key rotation" "No key rotation mechanism found"
fi
