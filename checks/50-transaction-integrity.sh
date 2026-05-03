#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-50
name: Transaction Integrity
description: Checks float/double for money, RoundingMode, BigDecimal divide safety.
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
frameworks: PCI-DSS:4.0:6.2.4, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25
PRESTON_META

# P-50: Transaction Integrity — Decimal Type & Rounding
# Financial systems MUST use proper decimal types, never float/double for money.
echo "P-50: Transaction Integrity"
SRC="${SOURCE_DIR:-.}"
float_money=$(grep -rn --include="$SRC_EXT" \
  "$FLOAT_MONEY_PATTERN" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|_test\.go\|$BIG_DECIMAL_TYPE\|//\|/\*" | head -5)
if [[ -z "$float_money" ]]; then
  record "PASS" "P-50 No float for money" "No float/double used for monetary amounts"
else
  count=$(echo "$float_money" | wc -l)
  record "FAIL" "P-50 Float for money" "$count uses of float/double for monetary amounts (must be $BIG_DECIMAL_TYPE)"
fi

rounding=$(grep -rn --include="$SRC_EXT" \
  "$ROUNDING_MODE_PATTERN\|setScale\|divide.*scale\|StringFixed" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
if [[ -n "$rounding" ]]; then
  record "PASS" "P-50 Rounding mode" "Explicit rounding mode in financial calculations"
else
  record "FAIL" "P-50 Rounding mode" "No explicit rounding mode — risk of precision loss"
fi

divide_no_scale=$(grep -rn --include="$SRC_EXT" \
  '\.divide([^,)]*)[^,]*)\|\.Div(' "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go\|$ROUNDING_MODE_PATTERN\|scale\|StringFixed" | head -5)
if [[ -z "$divide_no_scale" ]]; then
  record "PASS" "P-50 Division safety" "All decimal divides specify scale"
else
  count=$(echo "$divide_no_scale" | wc -l)
  record "WARN" "P-50 Division safety" "$count decimal divide calls without explicit scale"
fi
