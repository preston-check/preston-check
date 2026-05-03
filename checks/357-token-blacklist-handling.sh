#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-357
name: Token Admin Freeze / Blacklist Handling
description: Verifies that systems using USDT, USDC, BUSD, or other admin-pause-capable stablecoins handle the case where the issuer freezes or blacklists an address mid-transaction. Token-admin freezes (e.g., USDC's blacklist function) can cause transfers to revert; downstream systems must surface this clearly rather than silently failing or stranding funds.
category: code-scan
severity: medium
languages: solidity, typescript, javascript, java, python, go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04
cwe: 754
false_positive_rate: high
performance_class: fast
origin: USDT and USDC have invoked their blacklist powers many times (often in response to OFAC requests); systems holding or routing these tokens can have transfers revert without warning.
PRESTON_META

echo "P-357: Token Admin Freeze Handling"

SRC="${SOURCE_DIR:-.}"

stablecoin_use=$(grep -rln --include="*.sol" --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" \
  -iE 'USDC|USDT|BUSD|EURC|TUSD|tether|circle.*stable' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$stablecoin_use" ]]; then
  record "SKIP" "P-357 Token freeze handling" "No admin-pause-capable stablecoin references detected"
  return 0 2>/dev/null || true
fi

# Check for blacklist / freeze handling
freeze_handling=$(grep -rln --include="*.sol" --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" \
  -iE 'isBlacklisted|isFrozen|isBlocked|frozenStatus|blacklistCheck|tryTransfer|safeTransferOrFail|catch.*reverted|TokenFrozen' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$freeze_handling" ]]; then
  count=$(echo "$freeze_handling" | wc -l | tr -d ' ')
  record "PASS" "P-357 Token freeze handling" "$count file(s) handle stablecoin admin freeze/blacklist scenarios"
else
  record "WARN" "P-357 Token freeze handling" "Stablecoin usage detected without freeze/blacklist handling logic"
fi
