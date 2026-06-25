#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-52
name: Timing Attacks
description: Checks constant-time comparison for secrets, .equals() on passwords.
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
frameworks: PCI-DSS:4.0:3.6.1, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-1
PRESTON_META


# P-52: Timing Attack Prevention
# Password comparison, HMAC verification, token comparison must be constant-time.
echo "P-52: Timing Attacks"
SRC="${SOURCE_DIR:-.}"
constant_time=$(grep -rn --include="*.java" \
  "MessageDigest.isEqual\|constantTimeEquals\|timingSafeEqual\|SecureCompare\|slowEquals" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$constant_time" ]]; then
  record "PASS" "P-52 Constant-time compare" "Constant-time comparison for secrets found"
else
  record "WARN" "P-52 Constant-time compare" "No constant-time comparison — timing oracle risk on auth" "$(echo "$constant_time" | head -10)"
fi

string_equals_secret=$(grep -rn --include="*.java" \
  '\.equals.*password\|\.equals.*secret\|\.equals.*token\|\.equals.*signature\|\.equals.*hmac' \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|MessageDigest\|constantTime\|//\|enum\|Enum\|name()" | head -5)
if [[ -z "$string_equals_secret" ]]; then
  record "PASS" "P-52 No .equals() for secrets" "Secrets not compared with .equals()"
else
  count=$(echo "$string_equals_secret" | wc -l)
  record "WARN" "P-52 .equals() for secrets" "$count potential timing-vulnerable secret comparisons" "$(echo "$string_equals_secret" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "subtle\.ConstantTimeCompare|hmac\.Equal" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-52 Timing-Safe Comparison (Go)" "Constant-time comparison for secrets found in Go code"
  else
    record "WARN" "P-52 Timing-Safe Comparison (Go)" "No constant-time comparison found in Go code — timing oracle risk"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "ct_eq|ConstantTimeEq|ring::constant_time|subtle::" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-52 Timing-Safe Comparison (Rust)" "Constant-time comparison for secrets found in Rust code"
  else
    record "WARN" "P-52 Timing-Safe Comparison (Rust)" "No constant-time comparison found in Rust code — timing oracle risk"
  fi
fi
