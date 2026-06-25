#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-11
name: TLS/Encryption
description: Checks for plaintext HTTP, weak crypto (DES/RC4/MD5/ECB).
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
frameworks: PCI-DSS:4.0:4.2.1, SOC2:TSC-2017:CC6.7, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-2, CIS-v8:3.10
PRESTON_META


# P-11: TLS/Encryption enforcement
# Money-handling platforms must enforce HTTPS, use strong encryption,
# and never transmit sensitive data in plaintext.

echo "P-11: TLS & Encryption"

SRC="${SOURCE_DIR:-.}"

# Check for HTTP (non-HTTPS) URLs in source code
http_urls=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "http://" "$SRC/Common/src" "$SRC/Registration/src" "$SRC/Payments-logic/src" 2>/dev/null \
  | grep -v "localhost\|127\.0\.0\.1\|0\.0\.0\.0\|test\|Test\|target\|node_modules\|//.*http://\|http://schemas" \
  | head -10)

if [[ -z "$http_urls" ]]; then
  record "PASS" "P-11 No plaintext HTTP" "No non-localhost HTTP URLs in source"
else
  count=$(echo "$http_urls" | wc -l)
  record "WARN" "P-11 No plaintext HTTP" "$count non-localhost HTTP URLs found (should be HTTPS)" "$(echo "$http_urls" | head -10)"
fi

# Check for weak encryption algorithms
weak_crypto=$(grep -rn --include="*.java" \
  "DES\b\|RC4\|MD5\|SHA-1\|ECB\|AES/ECB\|Blowfish" \
  "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target\|// \|/\*\|comment\|log\.\|MD5.*Supefina" \
  | head -10)

if [[ -z "$weak_crypto" ]]; then
  record "PASS" "P-11 No weak crypto" "No DES/RC4/MD5/SHA-1/ECB patterns found"
else
  count=$(echo "$weak_crypto" | wc -l)
  record "WARN" "P-11 No weak crypto" "$count weak encryption patterns (DES/RC4/MD5/ECB)" "$(echo "$weak_crypto" | head -10)"
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
  record "WARN" "P-11 SSL enabled" "No SSL configuration found" "$(echo "$ssl_enabled" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "InsecureSkipVerify\s*:\s*true|DES\.|RC4\.|md5\.|sha1\." "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-11 TLS/Encryption (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-11 TLS/Encryption (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "danger_accept_invalid_certs|DANGER_ACCEPT_INVALID|DES|RC4|Md5|Sha1" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-11 TLS/Encryption (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-11 TLS/Encryption (Rust)" "No issues found in Rust files"
  fi
fi
