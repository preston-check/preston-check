#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-96
name: Integer Overflow Detection
description: Detects unchecked arithmetic on financial values across multiple languages.
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
frameworks: PCI-DSS:4.0:6.2.4, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.28, NIST-CSF:2.0:PR.DS-6
PRESTON_META


# P-96: Integer Overflow & Underflow Protection
# Checks for unguarded integer arithmetic on financial quantities.
# Long.MAX_VALUE overflows silently in Java, producing negative numbers.
echo "P-96: Integer Overflow"
SRC="${SOURCE_DIR:-.}"

# Check for unguarded long/int arithmetic on financial quantities
int_arith=$(grep -rn --include="*.java" \
  "long.*amount.*+\|long.*balance.*+\|int.*amount.*+\|int.*qty.*+\|long.*total.*+=\|int.*total.*+=" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|BigDecimal\|String" | head -5)
if [[ -z "$int_arith" ]]; then
  record "PASS" "P-96 Integer overflow" "No unguarded integer arithmetic on financial quantities"
else
  count=$(echo "$int_arith" | wc -l | tr -d ' ')
  record "WARN" "P-96 Integer overflow" "$count integer arithmetic operations on financial quantities — use BigDecimal or Math.addExact()" "$(echo "$int_arith" | head -10)"
fi

# Check for Math.addExact / Math.multiplyExact usage (safe overflow detection)
safe_math=$(grep -rn --include="*.java" "Math\.addExact\|Math\.multiplyExact\|Math\.subtractExact\|ArithmeticException" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$safe_math" ]]; then
  record "PASS" "P-96 Safe math" "Math.addExact/multiplyExact or ArithmeticException handling found"
else
  record "WARN" "P-96 Safe math" "No overflow-safe math operations — use Math.addExact() for integer financial calculations" "$(echo "$safe_math" | head -10)"
fi

# Check for currency amount stored as cents (long) without overflow guard
cents_pattern=$(grep -rn --include="*.java" \
  "long.*cents\|int.*cents\|amount.*100\|amount.*\*.*100\|price.*100\|\.intValue()" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -z "$cents_pattern" ]]; then
  record "PASS" "P-96 Cents conversion" "No risky cents conversion patterns"
else
  count=$(echo "$cents_pattern" | wc -l | tr -d ' ')
  record "WARN" "P-96 Cents conversion" "$count amount-to-cents conversions — verify overflow protection on multiply" "$(echo "$cents_pattern" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "int64.*amount|int.*balance|int.*total.*\+|int.*price" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-96 Integer Overflow (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-96 Integer Overflow (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "i64.*amount|u64.*balance|unchecked_add|wrapping_add" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-96 Integer Overflow (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-96 Integer Overflow (Rust)" "No issues found in Rust files"
  fi
fi
