#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-15
name: CORS/CSRF
description: Checks for wildcard origins, missing CSRF tokens.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.4.1, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.26, OWASP-API:2023:API8:2023, CIS-v8:16.9
PRESTON_META

# P-15: CORS and CSRF protection
# Public-facing financial APIs must have strict CORS and CSRF protection
# to prevent cross-site request forgery attacks.

echo "P-15: CORS & CSRF"

SRC="${SOURCE_DIR:-.}"

# Check for wildcard CORS (allow all origins)
wildcard_cors=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "Access-Control-Allow-Origin.*\*\|allowedOrigin.*\*\|cors.*origin.*\*" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|comment\|// " \
  | head -5)

if [[ -z "$wildcard_cors" ]]; then
  record "PASS" "P-15 No wildcard CORS" "No Access-Control-Allow-Origin: * found"
else
  count=$(echo "$wildcard_cors" | wc -l)
  record "FAIL" "P-15 No wildcard CORS" "$count wildcard CORS patterns — restricts to known origins"
fi

# Check for CSRF protection
csrf=$(grep -rn --include="*.java" --include="*.ts" \
  "csrf\|CSRF\|X-CSRF\|csrfProtection\|csrfToken\|X-Requested-With" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|disable" \
  | head -5)

if [[ -n "$csrf" ]]; then
  record "PASS" "P-15 CSRF protection" "CSRF protection mechanisms found"
else
  record "WARN" "P-15 CSRF protection" "No CSRF protection patterns found"
fi
