#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-325
name: Hacker / Scam Address Screening
description: Verifies that the platform screens against community-maintained lists of known hacker, scam, ransomware, and drainer addresses (in addition to OFAC). Sources include Etherscan tagged addresses, Scam Sniffer, ChainAbuse, and the Defillama Hack Database.
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
frameworks: NIST-CSF:2.0:DE.CM, FATF:2023:Rec.16
cwe: 20
false_positive_rate: medium
performance_class: fast
origin: Community lists capture hack-proceeds movement weeks before OFAC formally designates them. Real-time screening against community sources prevents inadvertent receipt or processing of dirty funds.
PRESTON_META

echo "P-325: Hacker / Scam Address Screening"

SRC="${SOURCE_DIR:-.}"

screen_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'scamSniffer|scam[_-]sniffer|chainAbuse|chain[_-]abuse|etherscan.*tagged|tagged[_-]address|hackerAddress|drainer[_-]list|known[_-]scam|blacklisted[_-]wallet|scam[_-]database|defillama.*hack|fortFenix|hapi\.|anti[_-]scam[_-]oracle' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

# Find any send / receive operations to determine relevance
crypto_ops=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'sendCrypto|receiveCrypto|withdraw[A-Z]|deposit[A-Z]|broadcastTransaction|monitorIncoming' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$crypto_ops" ]]; then
  record "SKIP" "P-325 Scam address screening" "No crypto send/receive code paths detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$screen_refs" ]]; then
  count=$(echo "$screen_refs" | wc -l | tr -d ' ')
  record "PASS" "P-325 Scam address screening" "$count file(s) reference community-maintained scam/hack address lists"
else
  record "WARN" "P-325 Scam address screening" "No screening against community scam/hack address lists detected (consider Scam Sniffer, ChainAbuse, hapi.one)"
fi
