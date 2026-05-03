#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-331
name: Dust Attack Detection
description: Verifies the platform detects and isolates dust transactions — small unsolicited transfers (typically below $0.01 equivalent) sent to taint a wallet's transaction graph for tracking, or to seed address-poisoning attacks. Treating dust UTXOs as ordinary funds in consolidation transactions reveals link information to attackers.
category: code-scan
severity: medium
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:DE.CM
cwe: 200
false_positive_rate: medium
performance_class: fast
origin: Bitcoin dust attacks (2018+) and Ethereum dust-poisoning (2023+) are widely-deployed surveillance and pre-attack reconnaissance techniques.
PRESTON_META

echo "P-331: Dust Attack Detection"

SRC="${SOURCE_DIR:-.}"

dust_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'dust[_-]threshold|dust[_-]limit|dust[_-]filter|dustAttack|dust[_-]detection|isDust|filterDust|min[_-]utxo[_-]value|consolidation[_-]filter' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Only relevant if there's UTXO/transaction handling
utxo_handling=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'UTXO|getUnspentTransactionOutputs|listUnspent|consolidate' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$utxo_handling" ]]; then
  record "SKIP" "P-331 Dust attack detection" "No UTXO/consolidation logic detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$dust_refs" ]]; then
  count=$(echo "$dust_refs" | wc -l | tr -d ' ')
  record "PASS" "P-331 Dust attack detection" "$count file(s) reference dust filtering"
else
  record "WARN" "P-331 Dust attack detection" "UTXO/consolidation logic without dust filtering" "$(echo "$utxo_handling" | head -10)"
fi
