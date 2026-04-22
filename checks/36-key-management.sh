#!/bin/bash
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
