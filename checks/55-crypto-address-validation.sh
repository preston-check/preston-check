#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-55
name: Crypto Address Validation
description: Checks address validation, whitelisting, AML screening.
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
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.26
PRESTON_META


# P-55: Cryptocurrency Address Validation
# Withdrawal addresses must be validated, whitelisted, and AML-screened.
echo "P-55: Crypto Address Security"
SRC="${SOURCE_DIR:-.}"
addr_validate=$(grep -rn --include="*.java" \
  "validateAddress\|validate_address\|isValidAddress\|addressValidat\|checksum.*address" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$addr_validate" ]]; then
  record "PASS" "P-55 Address validation" "Crypto address validation found"
else
  record "WARN" "P-55 Address validation" "No explicit crypto address validation"
fi

addr_whitelist=$(grep -rn --include="*.java" \
  "whitelist.*address\|external_wallet\|whitelistExternalWallet\|fireblocks_whitelist" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$addr_whitelist" ]]; then
  record "PASS" "P-55 Address whitelisting" "Withdrawal address whitelisting found"
else
  record "WARN" "P-55 Address whitelisting" "No withdrawal address whitelist"
fi

aml_screen=$(grep -rn --include="*.java" \
  "btrace\|amlcrypto\|chainalysis\|Btrace\|AML.*check\|screen.*address\|sanctions" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$aml_screen" ]]; then
  record "PASS" "P-55 AML screening" "Crypto address AML screening found (Btrace/Chainalysis)"
else
  record "WARN" "P-55 AML screening" "No crypto address AML screening"
fi
