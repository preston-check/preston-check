#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-337
name: Wallet Compromise Behavioral Indicators
description: Verifies that the platform monitors wallet behavior for compromise indicators — unusual time-of-day, geo-mismatch, sudden balance drain, atypical recipient address, atypical asset class. Behavioral anomalies precede or accompany 60%+ of ATO-driven theft.
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
frameworks: NIST-CSF:2.0:DE.AE
cwe: 1295
false_positive_rate: high
performance_class: fast
origin: Bank-grade fraud detection extended to crypto withdrawals; Coinbase, Binance, and others apply behavioral anomaly detection on every withdrawal request.
PRESTON_META

echo "P-337: Compromise Indicators"

SRC="${SOURCE_DIR:-.}"

beh_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'anomalyDetection|behaviorBaseline|geoMismatch|geoVelocity|unusualLogin|deviceFingerprint|riskEngine|fraudScore|behavior[_-]anomaly|impossible[_-]travel|atypicalActivity|loginVelocity|withdrawalVelocity' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$beh_refs" ]]; then
  count=$(echo "$beh_refs" | wc -l | tr -d ' ')
  record "PASS" "P-337 Compromise indicators" "$count file(s) reference behavioral anomaly / fraud detection"
else
  record "WARN" "P-337 Compromise indicators" "No behavioral anomaly detection found for wallet activity" "$(echo "$beh_refs" | head -10)"
fi
