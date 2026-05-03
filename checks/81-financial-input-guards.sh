#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-81
name: Financial Input Guards
description: Financial Input Guards security check (see COMPLIANCE_MAPPING.md for details).
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
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

# P-81: Financial Input Validation Guards
# Checks for numeric overflow, negative amount deposits, type coercion attacks,
# integer overflow, and boundary value exploitation in financial operations.
echo "P-81: Financial Input Guards"
SRC="${SOURCE_DIR:-.}"

# Check for negative amount validation on deposits
negative_deposit=$(grep -rn --include="$SRC_EXT" \
  "$NEGATIVE_AMOUNT_PATTERN\|amount.*negative\|amount.*must.*positive\|validateAmount\|amount.*check" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -5)
if [[ -n "$negative_deposit" ]]; then
  count=$(echo "$negative_deposit" | wc -l | tr -d ' ')
  record "PASS" "P-81 Negative amount" "$count negative/zero amount checks found"
else
  record "FAIL" "P-81 Negative amount" "No negative amount validation — deposits/withdrawals with negative amounts enable theft"
fi

# Check for numeric overflow protection
overflow=$(grep -rn --include="$SRC_EXT" \
  "MAX_VALUE\|overflow\|Long\.MAX\|Integer\.MAX\|max.*amount\|amount.*max\|amount.*>.*[0-9]\{7,\}\|MAX_AMOUNT\|AMOUNT_LIMIT\|math\.MaxInt\|math\.MaxFloat" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -3)
if [[ -n "$overflow" ]]; then
  record "PASS" "P-81 Overflow protection" "Numeric overflow protection found"
else
  record "WARN" "P-81 Overflow protection" "No explicit numeric overflow protection — extremely large values can cause calculation errors"
fi

# Check for type coercion prevention (string-to-number, null amount)
type_coercion=$(grep -rn --include="$SRC_EXT" \
  "NumberFormatException\|parseDouble\|parseInt\|getAsBigDecimal\|getAsDouble\|isNumber\|instanceof.*Number\|tryParse\|strconv\.Parse\|strconv\.Atoi" \
  "$SRC" 2>/dev/null | grep -i "amount\|price\|qty\|fee\|balance" \
  | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -5)
if [[ -n "$type_coercion" ]]; then
  # Check if exceptions are handled
  handled=$(grep -rn --include="$SRC_EXT" "catch.*NumberFormat\|catch.*JsonSyntax\|catch.*ClassCast\|if.*err.*!=.*nil" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go" | head -3)
  if [[ -n "$handled" ]]; then
    record "PASS" "P-81 Type coercion" "Numeric parsing with error handling found"
  else
    record "WARN" "P-81 Type coercion" "Numeric parsing found but no error handling — invalid input (chars as numbers) can crash"
  fi
else
  record "WARN" "P-81 Type coercion" "No explicit type validation on financial inputs"
fi

# Check for precision/scale validation on monetary amounts
precision=$(grep -rn --include="$SRC_EXT" \
  "scale()\|precision()\|setScale\|DECIMAL.*precision\|decimal_places\|MAX_SCALE\|MAX_DECIMAL\|StringFixed\|Exponent" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -5)
if [[ -n "$precision" ]]; then
  record "PASS" "P-81 Precision control" "Decimal precision/scale enforcement found"
else
  record "WARN" "P-81 Precision control" "No precision/scale enforcement — amounts with 100 decimal places can cause performance issues"
fi

# Check for zero-amount transaction prevention
zero_amount=$(grep -rn --include="$SRC_EXT" \
  "amount.*==.*0\|amount.*equals.*ZERO\|qty.*==.*0\|qty.*equals.*ZERO\|zero.*amount\|empty.*transaction\|IsZero\|amount\.Sign" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -3)
if [[ -n "$zero_amount" ]]; then
  record "PASS" "P-81 Zero amount" "Zero-amount transaction prevention found"
else
  record "WARN" "P-81 Zero amount" "No zero-amount transaction prevention — zero-value txns can be used to probe the system"
fi

# Check for special float values (NaN, Infinity)
special_values=$(grep -rn --include="$SRC_EXT" \
  "isNaN\|isInfinite\|NaN\|Infinity\|POSITIVE_INFINITY\|NEGATIVE_INFINITY\|isFinite\|math\.IsNaN\|math\.IsInf" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|//\|/\*" | head -3)
if [[ -n "$special_values" ]]; then
  record "PASS" "P-81 Special values" "NaN/Infinity validation found"
else
  record "WARN" "P-81 Special values" "No NaN/Infinity validation — special float values bypass comparison operators"
fi
