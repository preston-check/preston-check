#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-305
name: DEX Slippage Protection
description: Detects DEX swap calls (Uniswap V2/V3, SushiSwap, Curve, Balancer) that use amountOutMin=0 or omit the deadline parameter. These calls accept any output amount and any timing, making them trivially exploitable via sandwich attacks where an attacker bots the transaction in the public mempool.
category: code-scan
severity: high
languages: solidity, typescript, javascript
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04
cwe: 1188
false_positive_rate: low
performance_class: fast
origin: Sandwich-attack MEV bots regularly extract value from unprotected swaps; estimated billions in cumulative loss to DeFi users.
PRESTON_META

echo "P-305: DEX Slippage Protection"

SRC="${SOURCE_DIR:-.}"

# Unsafe patterns: amountOutMin: 0 or amountOutMin = 0 in swap call construction
unsafe_amount=$(grep -rn --include="*.ts" --include="*.tsx" --include="*.js" --include="*.sol" \
  -E 'swapExact[A-Za-z]+ForTokens?[^,]*,\s*0\s*,|amountOutMin\s*:\s*0|amountOutMin\s*=\s*0' "$SRC" 2>/dev/null \
  | grep -v "/test/\|/spec/\|node_modules\|/mock" || true)

# Missing deadline: swapExact* calls where the deadline argument looks suspicious (uses block.timestamp directly without buffer)
missing_deadline=$(grep -rn --include="*.sol" \
  -E 'swapExact[A-Za-z]+\s*\([^)]*block\.timestamp\s*\)' "$SRC" 2>/dev/null \
  | grep -v "/test/\|node_modules\|/mock" || true)

unsafe_count=0
[[ -n "$unsafe_amount" ]]    && unsafe_count=$((unsafe_count + $(echo "$unsafe_amount" | wc -l | tr -d ' ')))
[[ -n "$missing_deadline" ]] && unsafe_count=$((unsafe_count + $(echo "$missing_deadline" | wc -l | tr -d ' ')))

if [[ $unsafe_count -eq 0 ]]; then
  record "PASS" "P-305 DEX slippage" "All DEX swaps appear to specify amountOutMin and a sensible deadline"
else
  record "FAIL" "P-305 DEX slippage" "$unsafe_count DEX swap(s) with amountOutMin=0 or block.timestamp deadline (no buffer)" "$(echo "$missing_deadline" | head -10)"
fi
