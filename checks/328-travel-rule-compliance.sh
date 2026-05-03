#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-328
name: Travel Rule Compliance (FATF Recommendation 16)
description: Verifies that outbound crypto transfers above the regulatory threshold ($1,000 USD in the US, €1,000 in EU, varies by jurisdiction) collect and transmit originator and beneficiary information (name, account number, address) per FATF Recommendation 16. Non-compliance is enforceable by FinCEN, FATF members, and EU MiCA.
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
frameworks: FATF:2023:Rec.16, FinCEN:31CFR1010.410, EU-TFR:2023, MiCA:2024
cwe: 20
false_positive_rate: high
performance_class: fast
origin: FATF Recommendation 16 ("Travel Rule") was extended to virtual asset service providers (VASPs) in 2019. Multi-jurisdiction enforcement intensified with the EU Transfer of Funds Regulation (Dec 2024) and MiCA application.
PRESTON_META

echo "P-328: Travel Rule Compliance"

SRC="${SOURCE_DIR:-.}"

# Find Travel Rule implementations
tr_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'travel[_-]rule|travelRule|TRP[_-]API|sygna|notabene|veriscope|trisa\.io|originator[_-]vasp|beneficiary[_-]vasp|originatorInfo|beneficiaryInfo|FATF[_-]Rec[_-]?16' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find outbound crypto sends
sends=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'sendCrypto|broadcastTransaction|withdrawCrypto|cryptoTransfer|sendCoins' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$sends" ]]; then
  record "SKIP" "P-328 Travel Rule" "No outbound crypto transfer code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$tr_refs" ]]; then
  count=$(echo "$tr_refs" | wc -l | tr -d ' ')
  record "PASS" "P-328 Travel Rule" "$count file(s) reference Travel Rule provider integration or originator/beneficiary fields"
else
  record "FAIL" "P-328 Travel Rule" "Outbound crypto transfers without Travel Rule originator/beneficiary handling" "$(echo "$sends" | head -10)"
fi
