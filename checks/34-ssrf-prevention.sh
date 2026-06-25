#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-34
name: SSRF Prevention
description: Checks user-supplied URLs in HTTP clients, metadata endpoint blocking.
category: code-scan
severity: high
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.2.4, ISO-27001:2022:8.26, OWASP-API:2023:API7, CIS-v8:13.4
PRESTON_META


# P-34: SSRF Prevention — OWASP API #7
echo "P-34: SSRF Prevention"
SRC="${SOURCE_DIR:-.}"

user_url=$(grep -rn --include="*.java" \
  "callbackUrl\|callback_url\|webhookUrl\|webhook_url\|redirectUrl\|notificationUrl" \
  "$SRC" 2>/dev/null | grep -i "httpClient\|restTemplate\|webClient\|fetch\|request\|URL\|URI" \
  | grep -v "test\|Test\|target" | head -5)
if [[ -z "$user_url" ]]; then
  record "PASS" "P-34 No user URLs to HTTP" "No user-supplied URLs passed to HTTP clients"
else
  count=$(echo "$user_url" | wc -l)
  record "WARN" "P-34 User URLs to HTTP" "$count potential SSRF vectors — user URLs in HTTP client calls" "$(echo "$user_url" | head -10)"
fi

metadata=$(grep -rn --include="*.java" \
  "169.254.169.254\|metadata.*block\|validateUrl.*internal\|isInternalUrl\|SSRF" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$metadata" ]]; then
  record "PASS" "P-34 Metadata protection" "AWS metadata endpoint protection found"
else
  record "WARN" "P-34 Metadata protection" "No explicit metadata endpoint (169.254.169.254) blocking" "$(echo "$metadata" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "callbackUrl|callback_url|webhookUrl|webhook_url|redirectUrl|notificationUrl" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-34 SSRF User URL Params (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-34 SSRF User URL Params (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "callbackUrl|callback_url|webhookUrl|webhook_url|redirectUrl" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-34 SSRF User URL Params (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-34 SSRF User URL Params (Rust)" "No issues found in Rust files"
  fi
fi
