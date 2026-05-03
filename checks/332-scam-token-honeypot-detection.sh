#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-332
name: Scam / Honeypot Token Detection
description: Verifies the platform pre-flight-tests incoming ERC-20 tokens for honeypot behavior — the contract accepts buys but reverts on sells, or applies a punitive fee that destroys value on transfer. Tools like GoPlus, TokenSniffer, Honeypot.is, or simulated-transfer testing detect these before customer balance is credited.
category: code-scan
severity: medium
languages: typescript, javascript, java, python, go, rust, solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:DE.CM
cwe: 20
false_positive_rate: medium
performance_class: fast
origin: Honeypot tokens are an active scam family producing thousands of new contracts daily. Auto-listing platforms without honeypot filtering credit users with worthless or transfer-restricted balances.
PRESTON_META

echo "P-332: Scam / Honeypot Token Detection"

SRC="${SOURCE_DIR:-.}"

honeypot_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'goplus|tokenSniffer|honeypot[_-]is|honeypot[_-]check|honeypotDetector|isHoneypot|scam[_-]token|maliciousToken|simulateTransfer|tokenSafetyCheck|de\.fi[_-]scanner|GoPlusLabs' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find token receipt / listing flows
token_receipt=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.sol" \
  -iE 'tokenReceived|onTokenReceived|listToken|addToken|whitelistToken|tokenListing|importToken|registerToken' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$token_receipt" ]]; then
  record "SKIP" "P-332 Honeypot detection" "No token receipt or listing code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$honeypot_refs" ]]; then
  count=$(echo "$honeypot_refs" | wc -l | tr -d ' ')
  record "PASS" "P-332 Honeypot detection" "$count file(s) reference honeypot/scam-token detection"
else
  record "WARN" "P-332 Honeypot detection" "Token receipt/listing without honeypot detection (consider GoPlus, TokenSniffer, simulated-transfer test)"
fi
