#!/bin/bash
# P-11: TLS/Encryption enforcement
# Money-handling platforms must enforce HTTPS, use strong encryption,
# and never transmit sensitive data in plaintext.

echo "P-11: TLS & Encryption"

SRC="${SOURCE_DIR:-.}"

# Check for HTTP (non-HTTPS) URLs in source code
http_urls=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  --max-count=10 "http://" "$SRC/Common/src" "$SRC/Registration/src" "$SRC/Payments-logic/src" 2>/dev/null \
  | grep -v "localhost\|127\.0\.0\.1\|0\.0\.0\.0\|test\|Test\|target\|node_modules\|//.*http://\|http://schemas" \
  | head -10)

if [[ -z "$http_urls" ]]; then
  record "PASS" "P-11 No plaintext HTTP" "No non-localhost HTTP URLs in source"
else
  count=$(echo "$http_urls" | wc -l)
  record "WARN" "P-11 No plaintext HTTP" "$count non-localhost HTTP URLs found (should be HTTPS)"
fi

# Check for weak encryption algorithms
weak_crypto=$(grep -rn --include="*.java" \
  --max-count=10 "DES\b\|RC4\|MD5\|SHA-1\|ECB\|AES/ECB\|Blowfish" \
  "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target\|// \|/\*\|comment\|log\.\|MD5.*Supefina" \
  | head -10)

if [[ -z "$weak_crypto" ]]; then
  record "PASS" "P-11 No weak crypto" "No DES/RC4/MD5/SHA-1/ECB patterns found"
else
  count=$(echo "$weak_crypto" | wc -l)
  record "WARN" "P-11 No weak crypto" "$count weak encryption patterns (DES/RC4/MD5/ECB)"
fi

# Check that SSL is enabled in application configs
ssl_enabled=$(grep -rn --include="*.yml" --include="*.yaml" \
  "ssl.*enabled.*true\|ssl.*port" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" \
  | head -5)

if [[ -n "$ssl_enabled" ]]; then
  record "PASS" "P-11 SSL enabled" "SSL configuration found in application config"
else
  record "WARN" "P-11 SSL enabled" "No SSL configuration found"
fi
