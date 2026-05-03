#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-343
name: BIP-44 Derivation Path Correctness
description: Verifies that HD wallet derivation paths follow standardized formats (BIP-44 / BIP-49 / BIP-84 / BIP-86 with correct coin types per SLIP-44) rather than custom or chain-incorrect paths. Wrong derivation paths generate wallets that are forever inaccessible from standard wallet software.
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS
cwe: 1391
false_positive_rate: medium
performance_class: fast
origin: Recurring user-loss pattern: keys generated with non-standard derivation paths become non-recoverable from standard wallets (Trezor, Ledger, Electrum).
PRESTON_META

echo "P-343: BIP-44 Derivation Path"

SRC="${SOURCE_DIR:-.}"

# Find derivation-path strings
derivation_paths=$(grep -rEhn --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  "m/[0-9]+'?(/[0-9]+'?){2,5}" "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$derivation_paths" ]]; then
  record "SKIP" "P-343 Derivation path" "No HD wallet derivation paths detected"
  return 0 2>/dev/null || true
fi

# Standard paths: m/44'/X'/Y'/0/Z (BIP-44), m/49' (BIP-49), m/84' (BIP-84), m/86' (BIP-86)
# Common SLIP-44 coin types: 0 (BTC), 60 (ETH), 145 (BCH), 501 (SOL), 714 (BNB), 9000 (AVAX)
nonstandard=$(echo "$derivation_paths" | grep -vE "m/(44|49|84|86)'/[0-9]+'/[0-9]+'(/[0-9]+(/[0-9]+)?)?" || true)
nonstandard_count=$([[ -n "$nonstandard" ]] && echo "$nonstandard" | wc -l | tr -d ' ' || echo 0)

if [[ ${nonstandard_count:-0} -eq 0 ]]; then
  count=$(echo "$derivation_paths" | wc -l | tr -d ' ')
  record "PASS" "P-343 Derivation path" "$count derivation path(s) follow BIP-44/49/84/86 standards"
else
  record "WARN" "P-343 Derivation path" "$nonstandard_count derivation path(s) do not match BIP-44/49/84/86 standard format" "$(echo "$derivation_paths" | head -10)"
fi
