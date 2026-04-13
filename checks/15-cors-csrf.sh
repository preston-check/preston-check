#!/bin/bash
# P-15: CORS and CSRF protection
# Public-facing financial APIs must have strict CORS and CSRF protection
# to prevent cross-site request forgery attacks.

echo "P-15: CORS & CSRF"

SRC="${SOURCE_DIR:-.}"

# Check for wildcard CORS (allow all origins)
wildcard_cors=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  --max-count=10 "Access-Control-Allow-Origin.*\*\|allowedOrigin.*\*\|cors.*origin.*\*" \
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
  --max-count=5 "csrf\|CSRF\|X-CSRF\|csrfProtection\|csrfToken\|X-Requested-With" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|disable" \
  | head -5)

if [[ -n "$csrf" ]]; then
  record "PASS" "P-15 CSRF protection" "CSRF protection mechanisms found"
else
  record "WARN" "P-15 CSRF protection" "No CSRF protection patterns found"
fi
