#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-340
name: Reorg Confirmation Depth Enforcement
description: Verifies that incoming deposits are not credited to user balances until a chain-appropriate confirmation depth is met (Bitcoin: 6 blocks, Ethereum: 12-32 blocks, Polygon: 64+, BSC: 15+). Crediting balance on confirmation 0 or 1 exposes the platform to chain reorganization (reorg) double-spend.
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
cwe: 367
false_positive_rate: low
performance_class: fast
origin: Multiple exchanges have lost millions to reorg double-spend attacks (Ethereum Classic 2019-2020, Bitcoin Gold). Confirmation depth is the standard control.
PRESTON_META

echo "P-340: Reorg Confirmation Depth"

SRC="${SOURCE_DIR:-.}"

deposit_files=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'onDeposit|handleDeposit|depositReceived|creditBalance|incomingTransaction' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$deposit_files" ]]; then
  record "SKIP" "P-340 Reorg depth" "No deposit-handling code detected"
  return 0 2>/dev/null || true
fi

unsafe=0
total=0
for f in $deposit_files; do
  ((total++))
  if ! grep -qE 'confirmations\s*[><=]+\s*[0-9]+|requiredConfirmations|MIN_CONFIRMATIONS|confirmation[_-]depth|blockNumber.*-.*[0-9]+|finalized|safe[_-]block' "$f" 2>/dev/null; then
    ((unsafe++))
  fi
done

if [[ $unsafe -eq 0 ]]; then
  record "PASS" "P-340 Reorg depth" "$total deposit handler(s) enforce confirmation depth"
else
  record "FAIL" "P-340 Reorg depth" "$unsafe of $total deposit handler(s) lack confirmation-depth enforcement"
fi
