#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-336
name: Tainted Funds Source Trace
description: Verifies that incoming deposits trace the source wallet's recent provenance (last N hops) for connections to sanctioned addresses, mixers, hack-proceeds wallets, or darknet markets. Surface-level address screening alone misses funds that pass through one hop of laundering.
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
frameworks: FATF:2023:Rec.10, OFAC:2024, FinCEN:31CFR1010
cwe: 20
false_positive_rate: high
performance_class: fast
origin: OFAC and FinCEN guidance call for source-of-funds analysis beyond direct sender screening; chain analytics providers (Chainalysis, TRM) offer multi-hop trace APIs for this.
PRESTON_META

echo "P-336: Tainted Funds Source Trace"

SRC="${SOURCE_DIR:-.}"

trace_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'sourceOfFunds|fundsTrace|fundsProvenance|chainTrace|multiHopTrace|hopAnalysis|sourceWalletAnalysis|directExposure|indirectExposure|chainalysis.*kyt|trm.*trace|incomingExposure' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find deposit/incoming flows
deposits=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'onDeposit|handleDeposit|depositReceived|incomingTransaction|onIncoming|monitorDeposits' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$deposits" ]]; then
  record "SKIP" "P-336 Tainted funds trace" "No deposit-handling code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$trace_refs" ]]; then
  count=$(echo "$trace_refs" | wc -l | tr -d ' ')
  record "PASS" "P-336 Tainted funds trace" "$count file(s) reference source-of-funds tracing"
else
  record "FAIL" "P-336 Tainted funds trace" "Deposits handled without multi-hop source-of-funds tracing" "$(echo "$deposits" | head -10)"
fi
