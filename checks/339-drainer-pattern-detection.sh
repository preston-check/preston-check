#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-339
name: Wallet Drainer Pattern Detection
description: Verifies the platform detects drainer-pattern transactions (signTypedData / Permit / setApprovalForAll signatures crafted by phishing dApps to drain assets in one click) and warns the user before signing. Drainer kits (Inferno, Pink, Angel, Monkey) generate billions in cumulative loss.
category: code-scan
severity: high
languages: typescript, javascript
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04, NIST-CSF:2.0:DE.CM
cwe: 451
false_positive_rate: medium
performance_class: fast
origin: Drainer-as-a-service kits power industrial-scale phishing; ScamSniffer estimated $620M+ in confirmed drainer losses in 2024 alone.
PRESTON_META

echo "P-339: Drainer Pattern Detection"

SRC="${SOURCE_DIR:-.}"

drainer_refs=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -iE 'drainerDetection|drainer[_-]pattern|signTypedData[_-]warning|permit[_-]simulator|simulateTx|tx[_-]simulation|blockaid|wallet[_-]guard|forta|harpie|trustcheck|web3[_-]firewall' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find signTypedData / signMessage usage in wallet UI
sign_calls=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -E 'signTypedData|eth_signTypedData|personal_sign|setApprovalForAll' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$sign_calls" ]]; then
  record "SKIP" "P-339 Drainer detection" "No signing-flow code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$drainer_refs" ]]; then
  count=$(echo "$drainer_refs" | wc -l | tr -d ' ')
  record "PASS" "P-339 Drainer detection" "$count file(s) reference drainer detection / tx simulation"
else
  record "WARN" "P-339 Drainer detection" "Signing flows without drainer detection or tx simulation (consider Blockaid, Wallet Guard, Harpie)"
fi
