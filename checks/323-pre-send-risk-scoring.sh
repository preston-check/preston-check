#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-323
name: Pre-Send Risk Scoring (Blockchain Analytics)
description: Verifies that outbound transactions consult a blockchain analytics provider (Chainalysis, TRM Labs, Elliptic, Crystal, Scorechain) for destination-address risk scoring before broadcasting. Without this, your platform may unknowingly send funds to sanctioned, ransomware, or hack-proceeds addresses.
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
frameworks: FATF:2023:Rec.16, OFAC:2024, FinCEN:31CFR1010
cwe: 20
false_positive_rate: medium
performance_class: fast
origin: OFAC enforcement actions against multiple US-based crypto firms in 2022-2024 cited absence of pre-transaction blockchain-analytics screening as a contributing factor.
PRESTON_META

echo "P-323: Pre-Send Risk Scoring"

SRC="${SOURCE_DIR:-.}"

# Find blockchain analytics references
analytics_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'chainalysis|chainAnalysis|trmLabs|trm[_-]labs|elliptic|crystal[_-]blockchain|scorechain|merkle[_-]science|coinfirm|kyt[_-]api|risk[_-]score|address[_-]risk|wallet[_-]screening|transaction[_-]screening|sanctions[_-]check' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

# Find sending operations
send_files=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'sendCrypto|broadcastTransaction|withdraw[A-Z]|sendTransaction|sendRawTransaction' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$send_files" ]]; then
  record "SKIP" "P-323 Pre-send risk scoring" "No outbound send operations detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$analytics_refs" ]]; then
  count=$(echo "$analytics_refs" | wc -l | tr -d ' ')
  record "PASS" "P-323 Pre-send risk scoring" "$count file(s) integrate a blockchain analytics provider"
else
  record "FAIL" "P-323 Pre-send risk scoring" "Outbound send operations detected with no blockchain analytics integration" "$(echo "$send_files" | head -10)"
fi
