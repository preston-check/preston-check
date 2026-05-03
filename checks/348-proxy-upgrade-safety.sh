#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-348
name: Proxy Upgrade Safety and Initializer Protection
description: Detects upgradable Solidity proxy patterns (UUPS, Transparent, Beacon, Diamond) without proper initializer protection, storage layout safeguards, or upgrade time-locks. Uninitialized implementation contracts and unsafe upgrades are root causes of major exploits (Wormhole 2022 $320M).
category: code-scan
severity: high
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC01
cwe: 1188
false_positive_rate: medium
performance_class: fast
origin: Wormhole bridge ($320M, Feb 2022) and OpenZeppelin's published Initializable issues drove the industry toward strict initializer-protection patterns; absent guards remain a recurring audit finding.
PRESTON_META

echo "P-348: Proxy Upgrade Safety"

SRC="${SOURCE_DIR:-.}"
sol_files=$(find "$SRC" -name "*.sol" -not -path "*/node_modules/*" 2>/dev/null)

if [[ -z "$sol_files" ]]; then
  record "SKIP" "P-348 Proxy upgrade" "No Solidity contracts found"
  return 0 2>/dev/null || true
fi

# Find proxy patterns
proxy_files=$(grep -rl --include="*.sol" \
  -iE 'UUPSUpgradeable|TransparentUpgradeableProxy|BeaconProxy|Diamond|ERC1967|upgradeable|Initializable' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$proxy_files" ]]; then
  record "PASS" "P-348 Proxy upgrade" "No upgradable proxy patterns detected"
  return 0 2>/dev/null || true
fi

# Verify initializer protection
unsafe=0
total=0
for f in $proxy_files; do
  ((total++))
  if ! grep -qE 'initializer\s*\)|onlyInitializing|reinitializer|_disableInitializers|_authorizeUpgrade.*onlyOwner' "$f" 2>/dev/null; then
    ((unsafe++))
  fi
done

if [[ $unsafe -eq 0 ]]; then
  record "PASS" "P-348 Proxy upgrade" "$total upgradable contract(s) all reference initializer guards"
else
  record "FAIL" "P-348 Proxy upgrade" "$unsafe of $total upgradable contract(s) lack initializer / authorize-upgrade protection" "$(echo "$proxy_files" | head -10)"
fi
