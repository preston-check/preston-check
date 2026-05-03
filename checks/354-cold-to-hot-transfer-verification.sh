#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-354
name: Cold-to-Hot Transfer Interface Verification
description: Verifies that cold-to-hot wallet transfers use a verifiable, isolated signing interface that displays the actual transaction data being signed (not just a hash) and validates UI integrity before display. The Bybit February 2025 hack ($1.4B) succeeded because attackers replaced the signing interface during a routine cold-to-hot transfer, fooling signers into approving malicious smart contract logic.
category: code-scan
severity: critical
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.AC, CCSS:9.0:Level3
cwe: 451
false_positive_rate: high
performance_class: fast
origin: Bybit hack February 2025 — $1.4B lost when a signing-interface replacement during cold-to-hot transfer fooled signers. Now considered the standard control for institutional custody.
PRESTON_META

echo "P-354: Cold-to-Hot Transfer Verification"

SRC="${SOURCE_DIR:-.}"

# Find cold-to-hot or similar transfer flows
ch_flows=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'coldToHot|cold[_-]to[_-]hot|treasuryTransfer|reserveTransfer|warmingFromCold|sweep[_-]from[_-]cold|cold[_-]withdrawal' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$ch_flows" ]]; then
  record "SKIP" "P-354 Cold-to-hot verification" "No cold-to-hot transfer flows detected"
  return 0 2>/dev/null || true
fi

# Look for verification patterns
verification=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.md" \
  -iE 'parsedCalldata|decodedTransaction|displayTransaction|verifyContent|simulateBeforeSign|isolatedSigner|airgap[_-]signer|dedicatedSigningDevice|whatYouSeeIsWhatYouSign|wysiwys|ui[_-]integrity|hash[_-]display[_-]check' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -n "$verification" ]]; then
  count=$(echo "$verification" | wc -l | tr -d ' ')
  record "PASS" "P-354 Cold-to-hot verification" "$count file(s) reference signing-interface verification or isolated signers"
else
  record "FAIL" "P-354 Cold-to-hot verification" "Cold-to-hot transfer flows without signing-interface verification (Bybit Feb 2025 attack vector)" "$(echo "$verification" | head -10)"
fi
