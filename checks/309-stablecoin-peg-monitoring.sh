#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-309
name: Stablecoin Peg Monitoring
description: Detects stablecoin price feeds without deviation thresholds or automated circuit breakers. Stablecoin de-pegs (UST May 2022, USDC briefly March 2023) can cause cascading liquidations and protocol insolvency. Any system that treats a stablecoin as 1:1 USD without runtime peg verification is at risk during de-peg events.
category: code-scan
severity: medium
languages: solidity, typescript, javascript, java
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
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
  record "WARN" "P-309 Stablecoin peg" "$ref_count stablecoin reference(s) without observable peg-deviation or circuit-breaker logic"
fi
