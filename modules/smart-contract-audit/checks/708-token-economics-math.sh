#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-708
name: Token Economics Math (Rounding, Truncation, Order of Operations)
description: Detects token-amount math patterns prone to rounding-down exploitation, off-by-one in concentrated liquidity calculations, or order-of-operations bugs that cause precision loss. Cetus on Sui (May 2025, ~$220M) was a single-bit threshold comparison error.
category: code-scan
severity: high
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.6.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC03
cwe: 682
false_positive_rate: high
performance_class: fast
origin: Cetus integer-overflow incident, Balancer rounding bug Nov 2025, multiple AMM precision issues — recurring class where small math errors translate to large value extraction.
PRESTON_META

echo "P-708: Token Economics Math"

SRC="${SOURCE_DIR:-.}"
files=$(grep -rl --include="*.sol" -E '(amountIn|amountOut|liquidity|reserve0|reserve1).*[+\-*/]' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$files" ]]; then
  record "SKIP" "P-708 Token math" "No AMM-style amount calculations detected"
  return 0 2>/dev/null || true
fi

# Look for division before multiplication (precision loss anti-pattern)
suspect_order=$(grep -rn --include="*.sol" -E '\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*/\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)\s*\*' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

# Look for explicit precision libraries
prec=$(grep -rln --include="*.sol" -iE 'FixedPoint|FixedPointMathLib|FullMath|ABDKMath|PRBMath|UD60x18|SD59x18' "$SRC" 2>/dev/null || true)

s_count=$([[ -n "$suspect_order" ]] && echo "$suspect_order" | wc -l | tr -d ' ' || echo 0)
p_count=$([[ -n "$prec" ]] && echo "$prec" | wc -l | tr -d ' ' || echo 0)

if [[ ${s_count:-0} -eq 0 && ${p_count:-0} -gt 0 ]]; then
  record "PASS" "P-708 Token math" "Precision libraries in use ($p_count file(s)); no division-before-multiplication anti-patterns"
elif [[ ${s_count:-0} -gt 0 ]]; then
  record "FAIL" "P-708 Token math" "$s_count division-before-multiplication pattern(s) — precision loss / Cetus-class risk" "$(echo "$suspect_order" | head -10)"
else
  record "WARN" "P-708 Token math" "Token math without observable precision library (PRBMath, FixedPointMathLib, etc.)" "$(echo "$files" | head -10)"
fi
