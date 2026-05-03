#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-77
name: Withdrawal Controls
description: Detects withdrawal limits, address whitelist, cooldown, 2FA on withdrawals.
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
