#!/bin/bash
# P-97: Division Precision & Rounding Consistency
# In financial systems, different rounding on the same calculation in different places
# creates penny discrepancies that accumulate into reconciliation nightmares.
echo "P-97: Division Precision"
SRC="${SOURCE_DIR:-.}"

# Check for BigDecimal.divide() without explicit scale and RoundingMode
unsafe_divide=$(grep -rn --include="*.java" '\.divide(' "$SRC" 2>/dev/null \
  | grep -v "RoundingMode\|HALF_UP\|HALF_EVEN\|HALF_DOWN\|CEILING\|FLOOR\|scale" \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -z "$unsafe_divide" ]]; then
  record "PASS" "P-97 Safe division" "All BigDecimal.divide() calls specify scale and RoundingMode"
else
  count=$(echo "$unsafe_divide" | wc -l | tr -d ' ')
  record "FAIL" "P-97 Safe division" "$count BigDecimal.divide() without scale/RoundingMode — causes ArithmeticException on non-terminating decimals"
fi

# Check for consistent rounding mode across the codebase
rounding_modes=$(grep -rn --include="*.java" "RoundingMode\.\|HALF_UP\|HALF_EVEN\|HALF_DOWN\|CEILING\|FLOOR\|UNNECESSARY" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" \
  | grep -oP 'RoundingMode\.\w+|HALF_UP|HALF_EVEN|HALF_DOWN|CEILING|FLOOR' | sort | uniq -c | sort -rn)
if [[ -n "$rounding_modes" ]]; then
  primary=$(echo "$rounding_modes" | head -1 | awk '{print $2}')
  count=$(echo "$rounding_modes" | wc -l | tr -d ' ')
  if [[ $count -le 2 ]]; then
    record "PASS" "P-97 Rounding consistency" "Consistent rounding mode: $primary"
  else
    record "WARN" "P-97 Rounding consistency" "$count different rounding modes in use — inconsistent rounding causes reconciliation drift"
  fi
else
  record "WARN" "P-97 Rounding consistency" "No explicit RoundingMode found — financial calculations must specify rounding"
fi

# Check for floating-point comparison (== on doubles)
float_compare=$(grep -rn --include="*.java" \
  "==.*0\.0\|==.*0\.0f\|!=.*0\.0\|amount == \|price == \|balance == \|fee == " \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|BigDecimal\|compareTo\|null" | head -5)
if [[ -z "$float_compare" ]]; then
  record "PASS" "P-97 Float comparison" "No floating-point equality comparisons on financial values"
else
  count=$(echo "$float_compare" | wc -l | tr -d ' ')
  record "WARN" "P-97 Float comparison" "$count float equality comparisons — use BigDecimal.compareTo() instead of =="
fi
