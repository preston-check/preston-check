#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-333
name: Unverified Contract Quarantine
description: Verifies that incoming tokens or NFTs originating from unverified contract addresses (no published source code on Etherscan / Polygonscan / equivalent) are quarantined or flagged for manual review rather than auto-credited. Unverified contracts cannot be audited and frequently embed malicious behavior.
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
frameworks: NIST-CSF:2.0:DE.CM
cwe: 1357
false_positive_rate: high
performance_class: fast
origin: Auto-listing platforms have repeatedly credited users with unverified-contract tokens that turned out to be malicious; Etherscan source verification is the de facto trust signal.
PRESTON_META

echo "P-333: Unverified Contract Quarantine"

SRC="${SOURCE_DIR:-.}"

verify_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'isVerified|sourceVerified|etherscan.*getsourcecode|contract[_-]verification|verified[_-]contract|quarantine[_-]contract|unverified[_-]contract|trust[_-]score' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$verify_refs" ]]; then
  count=$(echo "$verify_refs" | wc -l | tr -d ' ')
  record "PASS" "P-333 Unverified contracts" "$count file(s) reference contract verification or quarantine"
else
  record "WARN" "P-333 Unverified contracts" "No contract source-verification check found in receipt flows"
fi
