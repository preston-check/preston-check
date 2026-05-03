#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-700
name: Storage Layout Collision (Proxy Upgrades)
description: Detects proxy / implementation contract pairs where storage slot ordering may collide on upgrade. Solidity assigns storage slots sequentially; if an upgrade moves a state variable to a different slot, all reads/writes to that variable corrupt unrelated state. Critical for OpenZeppelin Transparent and UUPS proxy patterns.
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.6.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC01, CWE:1188
cwe: 1188
false_positive_rate: high
performance_class: fast
origin: Storage collision is a recurring proxy-upgrade incident; OpenZeppelin's Upgrades plugin specifically exists to prevent this class of bug.
PRESTON_META

echo "P-700: Storage Layout Collision (Proxy Upgrades)"

SRC="${SOURCE_DIR:-.}"
proxy_files=$(grep -rl --include="*.sol" -E "TransparentUpgradeableProxy|UUPSUpgradeable|@openzeppelin/contracts-upgradeable|Initializable" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/mock/|node_modules" || true)

if [[ -z "$proxy_files" ]]; then
  record "SKIP" "P-700 Storage collision" "No upgradeable proxy contracts detected"
  return 0 2>/dev/null || true
fi

# Look for storage-gap declarations (the canonical defense against collision)
gap=$(grep -rln --include="*.sol" -E "uint256\[\s*[0-9]+\s*\]\s+private\s+__gap\b|uint256\[\s*[0-9]+\s*\]\s+__gap" "$SRC" 2>/dev/null || true)
ozcheck=$(grep -rln --include="*.sol" --include="*.json" -iE "@openzeppelin/upgrades|hardhat-upgrades|validateUpgrade" "$SRC" 2>/dev/null || true)

p_count=$(echo "$proxy_files" | wc -l | tr -d ' ')
g_count=$([[ -n "$gap" ]] && echo "$gap" | wc -l | tr -d ' ' || echo 0)
oz_count=$([[ -n "$ozcheck" ]] && echo "$ozcheck" | wc -l | tr -d ' ' || echo 0)

if [[ ${g_count:-0} -gt 0 || ${oz_count:-0} -gt 0 ]]; then
  record "PASS" "P-700 Storage collision" "$p_count proxy contract(s); storage-gap or OZ-Upgrades validation present"
else
  sample=$(echo "$proxy_files" | head -10)
  record "FAIL" "P-700 Storage collision" "$p_count proxy contract(s) without __gap or OpenZeppelin upgrades validation" "$sample"
fi
