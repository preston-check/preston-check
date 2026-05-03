#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-54
name: API Key Management
description: Checks key expiration, permission scoping.
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
frameworks: PCI-DSS:4.0:8.6, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.5, OWASP-API:2023:API2, CIS-v8:6.2
PRESTON_META


# P-54: API Key Lifecycle Management
# Keys must have expiration, rotation, scope limits, and usage logging.
echo "P-54: API Key Management"
SRC="${SOURCE_DIR:-.}"
key_expiry=$(grep -rn --include="*.java" --include="*.sql" \
  "expires_on\|key.*expir\|api_key.*valid\|token.*expir" "$SRC" 2>/dev/null \
  | grep -i "api.*key\|bloxpay_api" | grep -v "test\|Test\|target" | head -3)
if [[ -n "$key_expiry" ]]; then
  record "PASS" "P-54 API key expiry" "API keys have expiration dates"
else
  record "WARN" "P-54 API key expiry" "No API key expiration found" "$(echo "$key_expiry" | head -10)"
fi

key_scope=$(grep -rn --include="*.java" --include="*.sql" \
  "permissions\|scope\|allowed_ip\|ip_whitelist" "$SRC" 2>/dev/null \
  | grep -i "api.*key\|hmac\|bloxpay_api" | grep -v "test\|Test\|target" | head -3)
if [[ -n "$key_scope" ]]; then
  record "PASS" "P-54 API key scoping" "API keys have permission/IP scoping"
else
  record "WARN" "P-54 API key scoping" "No API key scope restrictions" "$(echo "$key_scope" | head -10)"
fi
