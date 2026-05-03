#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-99
name: Boundary Values
description: Detects missing zero, max-value, and edge-case handling on financial inputs.
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


# P-99: Boundary Value Protection
# Checks for boundary condition handling: max amounts, min amounts, exact thresholds,
# zero handling, and edge cases that attackers exploit.
echo "P-99: Boundary Values"
SRC="${SOURCE_DIR:-.}"

# Check for maximum amount enforcement
max_amount=$(grep -rn --include="*.java" --include="*.ts" \
  "MAX_AMOUNT\|max.*amount\|amount.*max\|AMOUNT_LIMIT\|MAX_TRANSACTION\|maximum.*value" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$max_amount" ]]; then
  record "PASS" "P-99 Maximum amount" "Maximum amount enforcement found"
else
  record "WARN" "P-99 Maximum amount" "No maximum amount constants — every financial input should have an upper bound"
fi

# Check for minimum amount enforcement (dust/micro-transaction prevention)
min_amount=$(grep -rn --include="*.java" --include="*.ts" \
  "MIN_AMOUNT\|min.*amount\|amount.*min\|minimum.*transaction\|dust\|too.*small\|below.*minimum" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$min_amount" ]]; then
  record "PASS" "P-99 Minimum amount" "Minimum amount enforcement found"
else
  record "WARN" "P-99 Minimum amount" "No minimum amount enforcement — micro-transactions can be used for probing"
fi

# Check for exact threshold handling (e.g., exactly $10,000 — above or equal to CTR threshold?)
threshold_handling=$(grep -rn --include="*.java" --include="*.ts" \
  ">=.*10000\|>.*10000\|<=.*threshold\|>=.*threshold\|compareTo.*threshold\|equals.*threshold" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$threshold_handling" ]]; then
  record "PASS" "P-99 Threshold handling" "Boundary threshold comparisons found"
else
  record "WARN" "P-99 Threshold handling" "No explicit threshold boundary handling — verify >= vs > at regulatory thresholds"
fi

# Check for empty string / null amount protection
null_amount=$(grep -rn --include="*.java" --include="*.ts" \
  "amount.*null\|null.*amount\|amount.*empty\|amount.*isBlank\|amount.*isEmpty\|NumberFormatException.*amount" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$null_amount" ]]; then
  record "PASS" "P-99 Null amount" "Null/empty amount protection found"
else
  record "WARN" "P-99 Null amount" "No explicit null/empty amount handling"
fi
