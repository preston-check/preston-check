#!/bin/bash
# P-54: API Key Lifecycle Management
# Keys must have expiration, rotation, scope limits, and usage logging.
echo "P-54: API Key Management"
SRC="${SOURCE_DIR:-.}"
key_expiry=$(grep -rn --include="*.java" --include="*.sql" --max-count=5 \
  "expires_on\|key.*expir\|api_key.*valid\|token.*expir" "$SRC" 2>/dev/null \
  | grep -i "api.*key\|bloxpay_api" | grep -v "test\|Test\|target" | head -3)
if [[ -n "$key_expiry" ]]; then
  record "PASS" "P-54 API key expiry" "API keys have expiration dates"
else
  record "WARN" "P-54 API key expiry" "No API key expiration found"
fi

key_scope=$(grep -rn --include="*.java" --include="*.sql" --max-count=5 \
  "permissions\|scope\|allowed_ip\|ip_whitelist" "$SRC" 2>/dev/null \
  | grep -i "api.*key\|hmac\|bloxpay_api" | grep -v "test\|Test\|target" | head -3)
if [[ -n "$key_scope" ]]; then
  record "PASS" "P-54 API key scoping" "API keys have permission/IP scoping"
else
  record "WARN" "P-54 API key scoping" "No API key scope restrictions"
fi
