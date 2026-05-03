#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-335
name: Counterparty Reputation Pre-Check
description: Verifies that high-value transactions (incoming or outgoing) consult counterparty reputation signals beyond OFAC and scam lists — wallet age, transaction volume profile, association with known exchanges or VASPs, time-since-first-transaction. Brand-new wallets with no history are higher risk regardless of clean OFAC status.
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
frameworks: FATF:2023:Rec.10, NIST-CSF:2.0:DE.AE
cwe: 20
false_positive_rate: medium
performance_class: fast
origin: Bank-grade KYC includes counterparty profiling (account age, activity patterns); the same discipline applies to crypto counterparties even when on-chain.
PRESTON_META

echo "P-335: Counterparty Reputation"

SRC="${SOURCE_DIR:-.}"

rep_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'walletAge|address[_-]age|first[_-]seen|firstTxBlock|counterparty[_-]score|reputation[_-]score|tx[_-]history[_-]depth|behaviorProfile|attribution[_-]label|exchange[_-]label|vasp[_-]label|cluster[_-]analysis' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$rep_refs" ]]; then
  count=$(echo "$rep_refs" | wc -l | tr -d ' ')
  record "PASS" "P-335 Counterparty reputation" "$count file(s) reference counterparty reputation/profiling"
else
  record "WARN" "P-335 Counterparty reputation" "No counterparty reputation profiling detected (wallet age, attribution, behavior)" "$(echo "$rep_refs" | head -10)"
fi
