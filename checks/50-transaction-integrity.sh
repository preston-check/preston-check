#!/bin/bash
# P-50: Transaction Integrity — BigDecimal & Rounding
# Financial systems MUST use BigDecimal, never float/double for money.
echo "P-50: Transaction Integrity"
SRC="${SOURCE_DIR:-.}"
float_money=$(grep -rn --include="*.java" --max-count=10 \
  "double.*amount\|float.*amount\|double.*balance\|float.*balance\|double.*price\|float.*price\|double.*fee\|float.*fee" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|BigDecimal\|//\|/\*" | head -5)
if [[ -z "$float_money" ]]; then
  record "PASS" "P-50 No float for money" "No float/double used for monetary amounts"
else
  count=$(echo "$float_money" | wc -l)
  record "FAIL" "P-50 Float for money" "$count uses of float/double for monetary amounts (must be BigDecimal)"
fi

rounding=$(grep -rn --include="*.java" --max-count=5 \
  "RoundingMode\|HALF_UP\|HALF_EVEN\|setScale\|divide.*scale" \
  "$SRC/Payments-logic" "$SRC/Portfolio-logic" "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$rounding" ]]; then
  record "PASS" "P-50 Rounding mode" "Explicit rounding mode in financial calculations"
else
  record "FAIL" "P-50 Rounding mode" "No explicit RoundingMode — risk of ArithmeticException and precision loss"
fi

divide_no_scale=$(grep -rn --include="*.java" --max-count=10 \
  '\.divide([^,)]*)[^,]*)' "$SRC/Payments-logic" "$SRC/Portfolio-logic" 2>/dev/null \
  | grep -v "test\|Test\|target\|RoundingMode\|scale" | head -5)
if [[ -z "$divide_no_scale" ]]; then
  record "PASS" "P-50 Division safety" "All BigDecimal divides specify scale"
else
  count=$(echo "$divide_no_scale" | wc -l)
  record "WARN" "P-50 Division safety" "$count BigDecimal.divide() calls without explicit scale"
fi
