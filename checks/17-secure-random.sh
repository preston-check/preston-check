#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-17
name: Secure Random
description: Checks for java.util.Random instead of SecureRandom.
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
frameworks: PCI-DSS:4.0:3.6.1, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-1, CIS-v8:3.11
PRESTON_META


# P-17: Secure randomness
# Financial systems must use SecureRandom, not Random, for all security-critical
# operations: tokens, codes, IDs, keys, nonces.

echo "P-17: Secure Randomness"

SRC="${SOURCE_DIR:-.}"

# Check for java.util.Random in security-sensitive contexts
insecure_random=$(grep -rn --include="*.java" \
  "new Random()\|java.util.Random\|Math.random()" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|SecureRandom" \
  | head -10)

if [[ -z "$insecure_random" ]]; then
  record "PASS" "P-17 Secure randomness" "No java.util.Random or Math.random() found"
else
  count=$(echo "$insecure_random" | wc -l)
  record "WARN" "P-17 Secure randomness" "$count uses of insecure Random (should be SecureRandom)" "$(echo "$insecure_random" | head -10)"
fi

# Check that SecureRandom IS used somewhere
secure_random=$(grep -rn --include="*.java" \
  "SecureRandom" \
  "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -3)

if [[ -n "$secure_random" ]]; then
  record "PASS" "P-17 SecureRandom present" "SecureRandom used in Common module"
else
  record "WARN" "P-17 SecureRandom present" "SecureRandom not found in Common — check other modules" "$(echo "$secure_random" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "rand\.New|rand\.Intn|rand\.Float64|math/rand" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-17 Secure randomness (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-17 Secure randomness (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "thread_rng|rand::random|SmallRng|StdRng::seed" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-17 Secure randomness (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-17 Secure randomness (Rust)" "No issues found in Rust files"
  fi
fi
