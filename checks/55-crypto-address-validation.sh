#!/bin/bash
# P-55: Cryptocurrency Address Validation
# Withdrawal addresses must be validated, whitelisted, and AML-screened.
echo "P-55: Crypto Address Security"
SRC="${SOURCE_DIR:-.}"
addr_validate=$(grep -rn --include="*.java" --max-count=5 \
  "validateAddress\|validate_address\|isValidAddress\|addressValidat\|checksum.*address" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$addr_validate" ]]; then
  record "PASS" "P-55 Address validation" "Crypto address validation found"
else
  record "WARN" "P-55 Address validation" "No explicit crypto address validation"
fi

addr_whitelist=$(grep -rn --include="*.java" --max-count=5 \
  "whitelist.*address\|external_wallet\|whitelistExternalWallet\|fireblocks_whitelist" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$addr_whitelist" ]]; then
  record "PASS" "P-55 Address whitelisting" "Withdrawal address whitelisting found"
else
  record "WARN" "P-55 Address whitelisting" "No withdrawal address whitelist"
fi

aml_screen=$(grep -rn --include="*.java" --max-count=5 \
  "btrace\|amlcrypto\|chainalysis\|Btrace\|AML.*check\|screen.*address\|sanctions" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$aml_screen" ]]; then
  record "PASS" "P-55 AML screening" "Crypto address AML screening found (Btrace/Chainalysis)"
else
  record "WARN" "P-55 AML screening" "No crypto address AML screening"
fi
