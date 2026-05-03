#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-96
name: Integer Overflow Detection
description: Detects unchecked arithmetic on financial values across multiple languages.
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
  record "WARN" "P-96 Integer overflow" "$count integer arithmetic operations on financial quantities — use BigDecimal or Math.addExact()"
fi

# Check for Math.addExact / Math.multiplyExact usage (safe overflow detection)
safe_math=$(grep -rn --include="*.java" "Math\.addExact\|Math\.multiplyExact\|Math\.subtractExact\|ArithmeticException" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$safe_math" ]]; then
  record "PASS" "P-96 Safe math" "Math.addExact/multiplyExact or ArithmeticException handling found"
else
  record "WARN" "P-96 Safe math" "No overflow-safe math operations — use Math.addExact() for integer financial calculations"
fi

# Check for currency amount stored as cents (long) without overflow guard
cents_pattern=$(grep -rn --include="*.java" \
  "long.*cents\|int.*cents\|amount.*100\|amount.*\*.*100\|price.*100\|\.intValue()" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -z "$cents_pattern" ]]; then
  record "PASS" "P-96 Cents conversion" "No risky cents conversion patterns"
else
  count=$(echo "$cents_pattern" | wc -l | tr -d ' ')
  record "WARN" "P-96 Cents conversion" "$count amount-to-cents conversions — verify overflow protection on multiply"
fi
