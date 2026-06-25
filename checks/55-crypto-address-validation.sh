#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-55
name: Crypto Address Validation
description: Checks address validation, whitelisting, AML screening.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
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
  record "WARN" "P-55 Address validation" "No explicit crypto address validation" "$(echo "$addr_validate" | head -10)"
fi

addr_whitelist=$(grep -rn --include="*.java" \
  "whitelist.*address\|external_wallet\|whitelistExternalWallet\|fireblocks_whitelist" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$addr_whitelist" ]]; then
  record "PASS" "P-55 Address whitelisting" "Withdrawal address whitelisting found"
else
  record "WARN" "P-55 Address whitelisting" "No withdrawal address whitelist" "$(echo "$addr_whitelist" | head -10)"
fi

aml_screen=$(grep -rn --include="*.java" \
  "btrace\|amlcrypto\|chainalysis\|Btrace\|AML.*check\|screen.*address\|sanctions" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$aml_screen" ]]; then
  record "PASS" "P-55 AML screening" "Crypto address AML screening found (Btrace/Chainalysis)"
else
  record "WARN" "P-55 AML screening" "No crypto address AML screening" "$(echo "$aml_screen" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "validateAddress|validate_address|isValidAddress|addressValidat|checksum.*address|whitelist.*address|external_wallet|chainalysis|AML.*check|sanctions|0x[0-9a-fA-F]{40}" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-55 Crypto Address Validation (Go)" "Address validation, whitelisting, or AML screening found in Go code"
  else
    record "WARN" "P-55 Crypto Address Validation (Go)" "No crypto address validation, whitelist, or AML screening in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "validate_address|is_valid_address|address_validat|checksum.*address|whitelist.*address|external_wallet|chainalysis|aml.*check|sanctions|H160|Address::|0x[0-9a-fA-F]{40}" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-55 Crypto Address Validation (Rust)" "Address validation, whitelisting, or AML screening found in Rust code"
  else
    record "WARN" "P-55 Crypto Address Validation (Rust)" "No crypto address validation, whitelist, or AML screening in Rust files"
  fi
fi
