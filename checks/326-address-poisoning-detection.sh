#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-326
name: Address Poisoning Detection
description: Verifies that the platform detects address poisoning attempts where attackers craft addresses with the same first/last 4 characters as a legitimate counterparty's address and send a small amount to plant the spoofed address in the target's transaction history. Users frequently copy from history, so the attack succeeds at next-send time.
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
frameworks: NIST-CSF:2.0:DE.CM, OWASP-API:2023:API3
cwe: 451
false_positive_rate: high
performance_class: fast
origin: Address poisoning generated $1.5M+ in single confirmed losses by mid-2024 (e.g., the $1.96M ETH loss reported by Cyvers in May 2024). The attack is technically simple but operationally pervasive.
PRESTON_META

echo "P-326: Address Poisoning Detection"

SRC="${SOURCE_DIR:-.}"

poison_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE 'address[_-]poisoning|poisoned[_-]address|spoofed[_-]address|first.*last.*chars|prefix.*suffix.*match|similar[_-]address|lookAlikeAddress|lookalike[_-]detection|truncated[_-]address[_-]match|address[_-]similarity' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find any address-display logic
addr_display=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'truncateAddress|formatAddress|shortenAddress|substring\s*\(\s*0\s*,\s*[6-8]\s*\).*substring\s*\([^)]*-[4-6]\)|slice\s*\(\s*0\s*,\s*[6-8]\s*\).*slice\s*\([^)]*-[4-6]\)' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$addr_display" ]]; then
  record "SKIP" "P-326 Address poisoning" "No address truncation or display logic found"
  return 0 2>/dev/null || true
fi

if [[ -n "$poison_refs" ]]; then
  count=$(echo "$poison_refs" | wc -l | tr -d ' ')
  record "PASS" "P-326 Address poisoning" "$count file(s) reference address-poisoning or look-alike detection"
else
  record "WARN" "P-326 Address poisoning" "Truncated-address display detected without look-alike/poisoning detection logic" "$(echo "$addr_display" | head -10)"
fi
