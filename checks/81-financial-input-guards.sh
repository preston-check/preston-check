#!/bin/bash
# P-81: Financial Input Validation Guards
# Checks for numeric overflow, negative amount deposits, type coercion attacks,
# integer overflow, and boundary value exploitation in financial operations.
echo "P-81: Financial Input Guards"
SRC="${SOURCE_DIR:-.}"

# Check for negative amount validation on deposits
negative_deposit=$(grep -rn --include="*.java" --include="*.ts" \
  "amount.*<=.*0\|amount.*<.*0\|amount.*compareTo.*ZERO.*<=\|amount.*negative\|amount.*must.*positive\|validateAmount\|amount.*check" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$negative_deposit" ]]; then
  count=$(echo "$negative_deposit" | wc -l | tr -d ' ')
  record "PASS" "P-81 Negative amount" "$count negative/zero amount checks found"
else
  record "FAIL" "P-81 Negative amount" "No negative amount validation — deposits/withdrawals with negative amounts enable theft"
fi

# Check for numeric overflow protection (BigDecimal max value, integer overflow)
overflow=$(grep -rn --include="*.java" --include="*.ts" \
  "MAX_VALUE\|overflow\|Long\.MAX\|Integer\.MAX\|max.*amount\|amount.*max\|amount.*>.*[0-9]\{7,\}\|MAX_AMOUNT\|AMOUNT_LIMIT" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$overflow" ]]; then
  record "PASS" "P-81 Overflow protection" "Numeric overflow protection found"
else
  record "WARN" "P-81 Overflow protection" "No explicit numeric overflow protection — extremely large values can cause calculation errors"
fi

# Check for type coercion prevention (string-to-number, null amount)
type_coercion=$(grep -rn --include="*.java" --include="*.ts" \
  "NumberFormatException\|parseDouble\|parseInt\|getAsBigDecimal\|getAsDouble\|isNumber\|instanceof.*Number\|tryParse" \
  "$SRC" 2>/dev/null | grep -i "amount\|price\|qty\|fee\|balance" \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$type_coercion" ]]; then
  # Check if exceptions are handled
  handled=$(grep -rn --include="*.java" "catch.*NumberFormat\|catch.*JsonSyntax\|catch.*ClassCast" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules" | head -3)
  if [[ -n "$handled" ]]; then
    record "PASS" "P-81 Type coercion" "Numeric parsing with error handling found"
  else
    record "WARN" "P-81 Type coercion" "Numeric parsing found but no error handling — invalid input (chars as numbers) can crash"
  fi
else
  record "WARN" "P-81 Type coercion" "No explicit type validation on financial inputs"
fi

# Check for precision/scale validation on monetary amounts
precision=$(grep -rn --include="*.java" --include="*.ts" \
  "scale()\|precision()\|setScale\|DECIMAL.*precision\|decimal_places\|MAX_SCALE\|MAX_DECIMAL" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$precision" ]]; then
  record "PASS" "P-81 Precision control" "Decimal precision/scale enforcement found"
else
  record "WARN" "P-81 Precision control" "No precision/scale enforcement — amounts with 100 decimal places can cause performance issues"
fi

# Check for zero-amount transaction prevention
zero_amount=$(grep -rn --include="*.java" --include="*.ts" \
  "amount.*==.*0\|amount.*equals.*ZERO\|qty.*==.*0\|qty.*equals.*ZERO\|zero.*amount\|empty.*transaction" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$zero_amount" ]]; then
  record "PASS" "P-81 Zero amount" "Zero-amount transaction prevention found"
else
  record "WARN" "P-81 Zero amount" "No zero-amount transaction prevention — zero-value txns can be used to probe the system"
fi

# Check for special float values (NaN, Infinity)
special_values=$(grep -rn --include="*.java" --include="*.ts" \
  "isNaN\|isInfinite\|NaN\|Infinity\|POSITIVE_INFINITY\|NEGATIVE_INFINITY\|isFinite" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$special_values" ]]; then
  record "PASS" "P-81 Special values" "NaN/Infinity validation found"
else
  record "WARN" "P-81 Special values" "No NaN/Infinity validation — special float values bypass comparison operators"
fi
