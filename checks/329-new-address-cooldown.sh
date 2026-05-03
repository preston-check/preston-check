#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-329
name: New-Address Withdrawal Cooldown
description: Verifies that newly added withdrawal destination addresses are subject to a cooling-off period (typically 24-72 hours) before they can be used for high-value transfers. The cooldown gives the legitimate account holder a chance to detect ATO-driven address additions before funds move.
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
frameworks: NIST-CSF:2.0:PR.AC, ISO-27001:2022:A.5.16
cwe: 425
false_positive_rate: low
performance_class: fast
origin: Industry-standard control across major exchanges (Coinbase, Binance, Kraken). ATO-driven instant withdrawals to attacker-controlled new addresses are blocked by even a 24h cooldown.
PRESTON_META

echo "P-329: New-Address Cooldown"

SRC="${SOURCE_DIR:-.}"

cooldown_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'cooldown[_-]period|cooling[_-]period|address[_-]cooldown|new[_-]address[_-]wait|withdrawal[_-]hold|holdPeriod|address[_-]hold|added[_-]at.*hours|whitelist[_-]wait' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

withdraw_files=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'function\s+(withdraw|sendCrypto|payout)|router\.(post|put).*withdraw' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$withdraw_files" ]]; then
  record "SKIP" "P-329 New-address cooldown" "No withdrawal endpoints detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$cooldown_refs" ]]; then
  count=$(echo "$cooldown_refs" | wc -l | tr -d ' ')
  record "PASS" "P-329 New-address cooldown" "$count file(s) reference new-address cooldown logic"
else
  record "WARN" "P-329 New-address cooldown" "Withdrawal endpoints detected without new-address cooldown control"
fi
