#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-30
name: HMAC Integrity
description: Checks HMAC filter coverage, replay protection, algorithm strength.
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
frameworks: PCI-DSS:4.0:4.2.1, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.24, OWASP-API:2023:API2
PRESTON_META


# P-30: HMAC Inter-Service Authentication Integrity
echo "P-30: HMAC Authentication"
SRC="${SOURCE_DIR:-.}"

api_modules=$(find "$SRC" -maxdepth 1 -name "*-api" -type d 2>/dev/null)
hmac_count=0
total_api=0
for mod in $api_modules; do
  ((total_api++))
  if grep -rq --include="*.java" --include="*.ts" "HmacAuthFilter\|HmacFilter\|hmacFilter" "$mod/src" 2>/dev/null; then
    ((hmac_count++))
  fi
done
if [[ $total_api -eq 0 ]]; then
  record "SKIP" "P-30 HMAC coverage" "No API modules found"
elif [[ $hmac_count -eq $total_api ]]; then
  record "PASS" "P-30 HMAC coverage" "All $total_api API modules have HMAC filters"
else
  record "WARN" "P-30 HMAC coverage" "$((total_api - hmac_count)) of $total_api API modules lack HMAC filter" "$(echo "$api_modules" | head -10)"
fi

replay=$(grep -rn --include="*.java" \
  "X-Timestamp\|timestamp.*sign\|nonce.*sign\|replay.*protect\|requestTime.*valid" \
  "$SRC" 2>/dev/null | grep -i "hmac\|sign\|auth.*filter" | grep -v "test\|Test\|target" | head -3)
if [[ -n "$replay" ]]; then
  record "PASS" "P-30 HMAC replay protection" "Timestamp/nonce in HMAC signature"
else
  record "WARN" "P-30 HMAC replay protection" "No replay protection in HMAC authentication" "$(echo "$replay" | head -10)"
fi

weak_algo=$(grep -rn --include="*.java" "HmacSHA1\b\|HmacMD5" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|HmacSHA256\|HmacSHA512" \
  | grep -v "google_authenticator\|TOTP\|SupefinaSign" \
  | head -3)
if [[ -z "$weak_algo" ]]; then
  record "PASS" "P-30 HMAC algorithm" "No weak HMAC algorithms (SHA1/MD5) — excluding external protocol requirements (TOTP RFC 6238, Supefina API)"
else
  record "FAIL" "P-30 HMAC algorithm" "Weak HMAC algorithm found (SHA1 or MD5)" "$(echo "$weak_algo" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "hmac\.New|hmac\.Equal|hmac\.Sum|sha256\.Sum|sha512\.Sum|X-Timestamp|nonce.*sign|replay.*protect" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-30 HMAC integrity (Go)" "HMAC integrity patterns found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "WARN" "P-30 HMAC integrity (Go)" "No HMAC integrity patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "hmac::Mac|hmac::Hmac|ring::hmac|sha2::Sha256|sha2::Sha512|X-Timestamp|nonce_sign|replay_protect" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-30 HMAC integrity (Rust)" "HMAC integrity patterns found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "WARN" "P-30 HMAC integrity (Rust)" "No HMAC integrity patterns found in Rust files"
  fi
fi
