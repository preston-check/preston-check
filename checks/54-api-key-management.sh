#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-54
name: API Key Management
description: Checks key expiration, permission scoping.
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "expires_on|key.*expir|api_key.*valid|token.*expir|permissions|scope|allowed_ip|ip_whitelist" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-54 API Key Management (Go)" "API key expiry or scoping mechanisms found in Go code"
  else
    record "WARN" "P-54 API Key Management (Go)" "No API key expiration or scope restrictions found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "expires_on|key.*expir|api_key.*valid|token.*expir|permissions|scope|allowed_ip|ip_whitelist" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-54 API Key Management (Rust)" "API key expiry or scoping mechanisms found in Rust code"
  else
    record "WARN" "P-54 API Key Management (Rust)" "No API key expiration or scope restrictions found in Rust files"
  fi
fi
