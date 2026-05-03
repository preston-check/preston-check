#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-316
name: Hot Wallet Concentration Limits
description: Verifies that hot wallets have operational balance caps and automated sweep policies to cold storage. A hot wallet without a cap holds the worst-case daily blast radius; sweep policies move funds out of hot once balance exceeds the working capital threshold.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS, NIST-CSF:2.0:DE.AE
cwe: 770
false_positive_rate: high
performance_class: fast
origin: Repeated exchange hacks (Bitmart 2021 $200M, KuCoin 2020 $280M, Bybit 2025 $1.5B) involved hot wallets holding multiples of operational working-capital requirements.
PRESTON_META

echo "P-316: Hot Wallet Concentration"

SRC="${SOURCE_DIR:-.}"

# Look for hot wallet caps or sweep policies
caps=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" --include="*.md" \
  -iE 'hotWalletLimit|hot[_-]wallet[_-]max|hot[_-]wallet[_-]cap|HOT_WALLET_THRESHOLD|sweepToCold|sweep[_-]to[_-]cold|autoSweep|maxHotBalance|warmFromCold|fundingThreshold' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

# Look for hot-wallet references at all
hot_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.md" \
  -iE 'hot[_-]wallet|hot[_-]storage' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules' || true)

if [[ -z "$hot_refs" ]]; then
  record "SKIP" "P-316 Hot wallet caps" "No hot-wallet references found"
  return 0 2>/dev/null || true
fi

if [[ -n "$caps" ]]; then
  cap_count=$(echo "$caps" | wc -l | tr -d ' ')
  record "PASS" "P-316 Hot wallet caps" "$cap_count file(s) reference hot-wallet caps or sweep-to-cold policies"
else
  record "WARN" "P-316 Hot wallet caps" "Hot-wallet references present but no caps or sweep-to-cold policies detected" "$(echo "$hot_refs" | head -10)"
fi
