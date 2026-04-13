#!/bin/bash
# P-30: HMAC Inter-Service Authentication Integrity
echo "P-30: HMAC Authentication"
SRC="${SOURCE_DIR:-.}"

api_modules=$(find "$SRC" -maxdepth 1 -name "*-api" -type d 2>/dev/null)
hmac_count=0
total_api=0
for mod in $api_modules; do
  ((total_api++))
  if grep -rq "HmacAuthFilter\|HmacFilter\|hmacFilter" "$mod/src" 2>/dev/null; then
    ((hmac_count++))
  fi
done
if [[ $total_api -eq 0 ]]; then
  record "SKIP" "P-30 HMAC coverage" "No API modules found"
elif [[ $hmac_count -eq $total_api ]]; then
  record "PASS" "P-30 HMAC coverage" "All $total_api API modules have HMAC filters"
else
  record "WARN" "P-30 HMAC coverage" "$((total_api - hmac_count)) of $total_api API modules lack HMAC filter"
fi

replay=$(grep -rn --include="*.java" --max-count=5 \
  "X-Timestamp\|timestamp.*sign\|nonce.*sign\|replay.*protect\|requestTime.*valid" \
  "$SRC" 2>/dev/null | grep -i "hmac\|sign\|auth.*filter" | grep -v "test\|Test\|target" | head -3)
if [[ -n "$replay" ]]; then
  record "PASS" "P-30 HMAC replay protection" "Timestamp/nonce in HMAC signature"
else
  record "WARN" "P-30 HMAC replay protection" "No replay protection in HMAC authentication"
fi

weak_algo=$(grep -rn --include="*.java" --max-count=5 "HmacSHA1\b\|HmacMD5" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|HmacSHA256\|HmacSHA512" | head -3)
if [[ -z "$weak_algo" ]]; then
  record "PASS" "P-30 HMAC algorithm" "No weak HMAC algorithms (SHA1/MD5)"
else
  record "FAIL" "P-30 HMAC algorithm" "Weak HMAC algorithm found (SHA1 or MD5)"
fi
