#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-15
name: CORS/CSRF
description: Checks for wildcard origins, missing CSRF tokens.
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
frameworks: PCI-DSS:4.0:6.4.1, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.26, OWASP-API:2023:API8, NIST-CSF:2.0:PR.DS-2, CIS-v8:16.9
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
  record "FAIL" "P-15 No wildcard CORS" "$count wildcard CORS patterns — restricts to known origins" "$(echo "$wildcard_cors" | head -10)"
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
  record "WARN" "P-15 CSRF protection" "No CSRF protection patterns found" "$(echo "$csrf" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "Access-Control-Allow-Origin.*\*|AllowAllOrigins" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-15 CORS/CSRF (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-15 CORS/CSRF (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "Access-Control-Allow-Origin.*\*|allow_any_origin|CorsLayer::permissive" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-15 CORS/CSRF (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-15 CORS/CSRF (Rust)" "No issues found in Rust files"
  fi
fi
