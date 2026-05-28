#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-97
name: Division Precision
description: Detects unsafe division patterns that lose precision in financial computations.
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


# P-97: Division Precision & Rounding Consistency
# In financial systems, different rounding on the same calculation in different places
# creates penny discrepancies that accumulate into reconciliation nightmares.
echo "P-97: Division Precision"
SRC="${SOURCE_DIR:-.}"

# Check for BigDecimal.divide() without explicit scale and RoundingMode
# For each .divide() call, check the line itself + next 2 lines for RoundingMode
unsafe_divide=""
while IFS= read -r file_and_line; do
  file=$(echo "$file_and_line" | cut -d: -f1)
  lineno=$(echo "$file_and_line" | cut -d: -f2)
  # Read 5 lines starting from the divide call (covers multi-line .divide(\n val,\n scale,\n RoundingMode\n))
  context=$(sed -n "${lineno},$((lineno+4))p" "$file" 2>/dev/null)
  # Skip BigInteger.divide() — integer division doesn't need RoundingMode
  if echo "$context" | grep -q "BigInteger"; then
    continue
  fi
  if ! echo "$context" | grep -qi "RoundingMode\|HALF_UP\|HALF_EVEN\|HALF_DOWN\|CEILING\|FLOOR"; then
    unsafe_divide+="${file_and_line}"$'\n'
  fi
done < <(grep -rn --include="*.java" '\.divide(' --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|//.*divide\|/\*" \
  | cut -d: -f1-2)
unsafe_divide=$(echo "$unsafe_divide" | sed '/^$/d')
if [[ -z "$unsafe_divide" ]]; then
  record "PASS" "P-97 Safe division" "All BigDecimal.divide() calls specify scale and RoundingMode"
else
  count=$(echo "$unsafe_divide" | wc -l | tr -d ' ')
  record "FAIL" "P-97 Safe division" "$count BigDecimal.divide() without scale/RoundingMode — causes ArithmeticException on non-terminating decimals"
  echo "$unsafe_divide" | head -10
fi

# Check for consistent rounding mode across the codebase
rounding_modes=$(grep -rn --include="*.java" "RoundingMode\.\|HALF_UP\|HALF_EVEN\|HALF_DOWN\|CEILING\|FLOOR\|UNNECESSARY" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" \
  | grep -oE 'RoundingMode\.[A-Z_]+|HALF_UP|HALF_EVEN|HALF_DOWN|CEILING|FLOOR' | sort | uniq -c | sort -rn)
if [[ -n "$rounding_modes" ]]; then
  primary=$(echo "$rounding_modes" | head -1 | awk '{print $2}')
  count=$(echo "$rounding_modes" | wc -l | tr -d ' ')
  if [[ $count -le 2 ]]; then
    record "PASS" "P-97 Rounding consistency" "Consistent rounding mode: $primary"
  else
    record "WARN" "P-97 Rounding consistency" "$count different rounding modes in use — inconsistent rounding causes reconciliation drift" "$(echo "$rounding_modes" | head -10)"
  fi
else
  record "WARN" "P-97 Rounding consistency" "No explicit RoundingMode found — financial calculations must specify rounding" "$(echo "$rounding_modes" | head -10)"
fi

# Check for floating-point comparison (== on doubles)
float_compare=$(grep -rn --include="*.java" \
  "==.*0\.0\|==.*0\.0f\|!=.*0\.0\|amount == \|price == \|balance == \|fee == " \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|BigDecimal\|compareTo\|null" | head -5)
if [[ -z "$float_compare" ]]; then
  record "PASS" "P-97 Float comparison" "No floating-point equality comparisons on financial values"
else
  count=$(echo "$float_compare" | wc -l | tr -d ' ')
  record "WARN" "P-97 Float comparison" "$count float equality comparisons — use BigDecimal.compareTo() instead of ==" "$(echo "$float_compare" | head -10)"
fi
