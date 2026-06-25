#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-68
name: Fee Manipulation
description: Detects negative fees, client-supplied fees, missing fee centralization.
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
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-6
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
  fee_calc=$(grep -rn --include="*.java" --include="*.ts" "fee\|spread\|commission\|markup" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|coffee\|caffee" | wc -l | tr -d ' ')
  if [[ "$fee_calc" -gt 5 ]]; then
    record "WARN" "P-68 Fee validation" "Fee calculations exist but no explicit fee validation guards (negative/zero/bypass)" "$(echo "$fee_calc" | head -10)"
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
  record "WARN" "P-68 Server-side fees" "$count endpoints accept fee from client request — fees must be computed server-side" "$(echo "$client_fee" | head -10)"
fi

# Check for fee consistency (same fee engine used everywhere)
fee_centralized=$(grep -rn --include="*.java" --include="*.ts" \
  "FeeEngine\|FeeService\|fee.*service\|fee.*calculator\|feeCalculat" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -5)
if [[ -n "$fee_centralized" ]]; then
  record "PASS" "P-68 Fee centralization" "Centralized fee engine/service found"
else
  # Check for scattered fee calculations
  scattered=$(grep -rn --include="*.java" "spread\|bps\|basis.*point\|fee.*percent" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|FeeEngine\|FeeService" | wc -l | tr -d ' ')
  if [[ "$scattered" -gt 3 ]]; then
    record "WARN" "P-68 Fee centralization" "$scattered scattered fee calculations — consolidate into single FeeEngine" "$(echo "$scattered" | head -10)"
  else
    record "PASS" "P-68 Fee centralization" "Fee calculations appear consolidated"
  fi
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "fee.*validation|validateFee|fee.*check|fee.*<=.*0|FeeService|fee.*service|fee.*calculator|feeCalculat|request.*fee|body.*fee" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-68 Fee Manipulation (Go)" "Fee validation/centralization patterns found in Go code"
  else
    record "WARN" "P-68 Fee Manipulation (Go)" "No fee validation or centralized fee service found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "fee.*validation|validate_fee|fee.*check|fee_service|fee_calculator|request.*fee|body.*fee" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-68 Fee Manipulation (Rust)" "Fee validation/centralization patterns found in Rust code"
  else
    record "WARN" "P-68 Fee Manipulation (Rust)" "No fee validation or centralized fee service found in Rust files"
  fi
fi
