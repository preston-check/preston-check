#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-57
name: Business Logic Abuse Prevention
description: Covers OWASP API6:2023. Checks for account creation rate limits, bulk operation guards, scraping prevention, and bot detection patterns (CAPTCHA, device fingerprinting).
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
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

# P-57: Business Logic Abuse Prevention — OWASP API6:2023
# Checks for rate limits on account creation, bulk operation guards, bot detection.
echo "P-57: Business Logic Abuse"
SRC="${SOURCE_DIR:-.}"

# Account creation rate limiting
reg_ratelimit=$(grep -rn --include="*.java" --include="*.ts" \
  "register\|signup\|createAccount\|create_account" "$SRC" 2>/dev/null \
  | grep -i "rateLimit\|throttle\|cooldown\|captcha\|recaptcha\|turnstile" \
  | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$reg_ratelimit" ]]; then
  record "PASS" "P-57 Registration rate limit" "Account creation has rate limiting or bot detection"
else
  reg_count=$(grep -rn --include="*.java" --include="*.ts" "register\|signup\|createAccount" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | wc -l | tr -d ' ')
  if [[ "$reg_count" -gt 0 ]]; then
    record "WARN" "P-57 Registration rate limit" "No rate limiting on $reg_count registration endpoints"
  else
    record "SKIP" "P-57 Registration rate limit" "No registration endpoints found"
  fi
fi

# Bulk operation guards
bulk_ops=$(grep -rn --include="*.java" --include="*.ts" \
  "batch\|bulk\|mass\|forEach.*create\|forEach.*delete\|forEach.*update" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$bulk_ops" ]]; then
  limit_check=$(echo "$bulk_ops" | grep -i "maxSize\|max_size\|limit\|MAX_BATCH\|PAGE_SIZE")
  if [[ -n "$limit_check" ]]; then
    record "PASS" "P-57 Bulk operation limits" "Bulk operations have size limits"
  else
    count=$(echo "$bulk_ops" | wc -l | tr -d ' ')
    record "WARN" "P-57 Bulk operation limits" "$count bulk operations without explicit size limits"
  fi
else
  record "PASS" "P-57 Bulk operation limits" "No bulk operation patterns found"
fi

# Bot detection patterns
bot_detection=$(grep -rn --include="*.java" --include="*.ts" --include="*.xml" --include="*.yml" \
  "captcha\|recaptcha\|turnstile\|device.*fingerprint\|bot.*detect\|challenge" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$bot_detection" ]]; then
  record "PASS" "P-57 Bot detection" "Bot detection/CAPTCHA patterns found"
else
  record "WARN" "P-57 Bot detection" "No CAPTCHA or bot detection patterns found"
fi
