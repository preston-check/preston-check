#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-68
name: Fee Manipulation
description: Fee Manipulation security check (see COMPLIANCE_MAPPING.md for details).
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

# P-68: Fee Manipulation Protection
# Validates that fees cannot be bypassed, set to negative, or manipulated client-side.
# Fee logic must be server-side only with validation guards.
echo "P-68: Fee Manipulation"
SRC="${SOURCE_DIR:-.}"

# Check for fee validation (negative fees, zero fees, fee bypass)
fee_validation=$(grep -rn --include="*.java" --include="*.ts" \
  "fee.*<=.*0\|fee.*<.*0\|fee.*negative\|fee.*validation\|validateFee\|validate.*fee\|fee.*check" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$fee_validation" ]]; then
  record "PASS" "P-68 Fee validation" "Fee validation checks found"
else
  # Check if there are fee calculations at all
  fee_calc=$(grep -rn --include="*.java" --include="*.ts" "fee\|spread\|commission\|markup" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|coffee\|caffee" | wc -l | tr -d ' ')
  if [[ "$fee_calc" -gt 5 ]]; then
    record "WARN" "P-68 Fee validation" "Fee calculations exist but no explicit fee validation guards (negative/zero/bypass)"
  else
    record "SKIP" "P-68 Fee validation" "No significant fee calculation patterns found"
  fi
fi

# Check for client-side fee acceptance (fees should NEVER be sent from client)
client_fee=$(grep -rn --include="*.java" --include="*.ts" \
  "request.*fee\|body.*fee\|param.*fee\|@Body.*fee\|req\.body\.fee\|funds_in.*fee" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|override\|admin" | head -3)
if [[ -z "$client_fee" ]]; then
  record "PASS" "P-68 Server-side fees" "No client-supplied fee parameters found"
else
  count=$(echo "$client_fee" | wc -l | tr -d ' ')
  record "WARN" "P-68 Server-side fees" "$count endpoints accept fee from client request — fees must be computed server-side"
fi

# Check for fee consistency (same fee engine used everywhere)
fee_centralized=$(grep -rn --include="*.java" --include="*.ts" \
  "FeeEngine\|FeeService\|fee.*service\|fee.*calculator\|feeCalculat" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -5)
if [[ -n "$fee_centralized" ]]; then
  record "PASS" "P-68 Fee centralization" "Centralized fee engine/service found"
else
  # Check for scattered fee calculations
  scattered=$(grep -rn --include="*.java" "spread\|bps\|basis.*point\|fee.*percent" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|FeeEngine\|FeeService" | wc -l | tr -d ' ')
  if [[ "$scattered" -gt 3 ]]; then
    record "WARN" "P-68 Fee centralization" "$scattered scattered fee calculations — consolidate into single FeeEngine"
  else
    record "PASS" "P-68 Fee centralization" "Fee calculations appear consolidated"
  fi
fi
