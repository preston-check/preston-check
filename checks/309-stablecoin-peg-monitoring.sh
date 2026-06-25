#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-309
name: Stablecoin Peg Monitoring
description: Detects stablecoin price feeds without deviation thresholds or automated circuit breakers. Stablecoin de-pegs (UST May 2022, USDC briefly March 2023) can cause cascading liquidations and protocol insolvency. Any system that treats a stablecoin as 1:1 USD without runtime peg verification is at risk during de-peg events.
category: code-scan
severity: medium
languages: solidity, typescript, javascript, java, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:DE.AE
cwe: 754
false_positive_rate: high
performance_class: fast
origin: Terra/UST collapse (May 2022, $40B+ wiped) and USDC's 2023 brief de-peg both caused systemic harm to integrating protocols that assumed 1:1 stablecoin pricing.
PRESTON_META

echo "P-309: Stablecoin Peg Monitoring"

SRC="${SOURCE_DIR:-.}"

# Find references to stablecoins and verify presence of peg-deviation logic
stable_refs=$(grep -rln --include="*.sol" --include="*.ts" --include="*.js" --include="*.java" \
  -iE 'USDC|USDT|DAI|FRAX|LUSD|TUSD|stablecoin|stable.*coin' "$SRC" 2>/dev/null \
  | grep -v "/test/\|/mock/\|node_modules" || true)

if [[ -z "$stable_refs" ]]; then
  record "SKIP" "P-309 Stablecoin peg" "No stablecoin references detected"
  return 0 2>/dev/null || true
fi

# Check for peg-deviation logic
peg_logic=$(grep -rln --include="*.sol" --include="*.ts" --include="*.js" --include="*.java" \
  -iE 'pegDeviation|peg.*threshold|deviationThreshold|circuit.*breaker|pause.*depeg|maxDeviation' "$SRC" 2>/dev/null || true)

ref_count=$(echo "$stable_refs" | wc -l | tr -d ' ')
peg_count=$([[ -n "$peg_logic" ]] && echo "$peg_logic" | wc -l | tr -d ' ' || echo 0)

if [[ ${peg_count:-0} -gt 0 ]]; then
  record "PASS" "P-309 Stablecoin peg" "$ref_count stablecoin reference(s); peg deviation logic present in $peg_count place(s)"
else
  record "WARN" "P-309 Stablecoin peg" "$ref_count stablecoin reference(s) without observable peg-deviation or circuit-breaker logic" "$(echo "$peg_logic" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "USDC|USDT|DAI|FRAX|LUSD|TUSD|stablecoin|stable.*coin|pegDeviation|peg.*threshold|deviationThreshold|circuit.*breaker" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-309 Stablecoin Peg Monitoring (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-309 Stablecoin Peg Monitoring (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "USDC|USDT|DAI|FRAX|LUSD|TUSD|stablecoin|stable.*coin|pegDeviation|peg.*threshold|deviationThreshold|circuit.*breaker" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-309 Stablecoin Peg Monitoring (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-309 Stablecoin Peg Monitoring (Rust)" "No issues found in Rust files"
  fi
fi
