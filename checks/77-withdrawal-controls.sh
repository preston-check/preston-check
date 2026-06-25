#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-77
name: Withdrawal Controls
description: Detects withdrawal limits, address whitelist, cooldown, 2FA on withdrawals.
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
frameworks: PCI-DSS:4.0:8.4.2, SOC2:TSC-2017:CC6.1, ISO-27001:2022:5.16, NIST-CSF:2.0:PR.AA-3, CIS-v8:6.3
PRESTON_META


# P-77: Withdrawal Controls & Fraud Prevention
# Outbound fund movements are the highest-risk operations and require
# multiple layers of validation, cooling periods, and approval workflows.
echo "P-77: Withdrawal Controls"
SRC="${SOURCE_DIR:-.}"

# Check for withdrawal amount limits
withdraw_limit=$(grep -rn --include="*.java" --include="*.ts" \
  "withdraw.*limit\|withdraw.*max\|max.*withdraw\|withdrawal.*threshold\|daily.*withdraw\|withdraw.*cap" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$withdraw_limit" ]]; then
  record "PASS" "P-77 Withdrawal limits" "Withdrawal amount limits found"
else
  record "WARN" "P-77 Withdrawal limits" "No explicit withdrawal limits" "$(echo "$withdraw_limit" | head -10)"
fi

# Check for withdrawal address whitelisting
address_whitelist=$(grep -rn --include="*.java" --include="*.ts" \
  "whitelist.*address\|whitelisted.*wallet\|approved.*address\|address.*approved\|trusted.*address\|address.*whitelist" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$address_whitelist" ]]; then
  record "PASS" "P-77 Address whitelist" "Withdrawal address whitelisting found"
else
  record "WARN" "P-77 Address whitelist" "No withdrawal address whitelisting — crypto withdrawals should only go to pre-approved addresses" "$(echo "$address_whitelist" | head -10)"
fi

# Check for withdrawal cooling period (new addresses)
withdraw_cooldown=$(grep -rn --include="*.java" --include="*.ts" \
  "cooldown.*withdraw\|cooling.*period\|new.*address.*delay\|24.*hour.*wait\|withdraw.*delay\|address.*lock" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$withdraw_cooldown" ]]; then
  record "PASS" "P-77 Withdrawal cooldown" "Withdrawal cooling period found"
else
  record "WARN" "P-77 Withdrawal cooldown" "No cooling period for new withdrawal addresses — delays prevent account takeover theft" "$(echo "$withdraw_cooldown" | head -10)"
fi

# Check for withdrawal 2FA requirement
withdraw_2fa=$(grep -rn --include="*.java" --include="*.ts" \
  "withdraw.*2fa\|withdraw.*code\|withdraw.*otp\|withdraw.*mfa\|2fa.*withdraw\|code.*withdraw" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$withdraw_2fa" ]]; then
  record "PASS" "P-77 Withdrawal 2FA" "2FA required for withdrawals"
else
  record "WARN" "P-77 Withdrawal 2FA" "No 2FA enforcement on withdrawals" "$(echo "$withdraw_2fa" | head -10)"
fi

# Check for large withdrawal manual review
manual_review=$(grep -rn --include="*.java" --include="*.ts" \
  "manual.*review\|manual.*approval\|human.*review\|admin.*approve\|compliance.*review\|large.*withdraw" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$manual_review" ]]; then
  record "PASS" "P-77 Manual review" "Large withdrawal manual review found"
else
  record "WARN" "P-77 Manual review" "No manual review for large withdrawals — should require human approval above threshold" "$(echo "$manual_review" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "withdraw.*limit|withdraw.*max|max.*withdraw|withdrawal.*threshold|daily.*withdraw|withdraw.*cap|whitelist.*address|approved.*address|trusted.*address|cooldown.*withdraw|cooling.*period|withdraw.*delay|address.*lock|withdraw.*2fa|withdraw.*otp|withdraw.*mfa|manual.*review|manual.*approval|human.*review|admin.*approve" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-77 Withdrawal controls (Go)" "$_go_count pattern(s) found in Go code"
  else
    record "WARN" "P-77 Withdrawal controls (Go)" "No withdrawal control patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "withdraw.*limit|withdraw.*max|max.*withdraw|withdrawal.*threshold|daily.*withdraw|withdraw.*cap|whitelist.*address|approved.*address|trusted.*address|cooldown.*withdraw|cooling.*period|withdraw.*delay|address.*lock|withdraw.*2fa|withdraw.*otp|withdraw.*mfa|manual.*review|manual.*approval|human.*review|admin.*approve" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-77 Withdrawal controls (Rust)" "$_rs_count pattern(s) found in Rust code"
  else
    record "WARN" "P-77 Withdrawal controls (Rust)" "No withdrawal control patterns found in Rust files"
  fi
fi
