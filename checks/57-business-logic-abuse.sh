#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-57
name: Business Logic Abuse Prevention
description: Covers OWASP API6:2023. Checks for account creation rate limits, bulk operation guards, scraping prevention, and bot detection patterns (CAPTCHA, device fingerprinting).
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
  reg_count=$(grep -rn --include="*.java" --include="*.ts" "register\|signup\|createAccount" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | wc -l | tr -d ' ')
  if [[ "$reg_count" -gt 0 ]]; then
    record "WARN" "P-57 Registration rate limit" "No rate limiting on $reg_count registration endpoints" "$(echo "$reg_count" | head -10)"
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
    record "WARN" "P-57 Bulk operation limits" "$count bulk operations without explicit size limits" "$(echo "$bulk_ops" | head -10)"
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
  record "WARN" "P-57 Bot detection" "No CAPTCHA or bot detection patterns found" "$(echo "$bot_detection" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "RateLimiter|ratelimit|throttle|captcha|recaptcha|turnstile|bot.*detect|maxSize|max_size|MAX_BATCH" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-57 Business Logic Abuse (Go)" "Rate limiting, bot detection, or bulk operation guards found in Go code"
  else
    record "WARN" "P-57 Business Logic Abuse (Go)" "No rate limiting, CAPTCHA, or bulk operation guards found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "governor|ratelimit|RateLimiter|captcha|recaptcha|turnstile|bot.*detect|max_size|MAX_BATCH" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-57 Business Logic Abuse (Rust)" "Rate limiting, bot detection, or bulk operation guards found in Rust code"
  else
    record "WARN" "P-57 Business Logic Abuse (Rust)" "No rate limiting, CAPTCHA, or bulk operation guards found in Rust files"
  fi
fi
