#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-324
name: OFAC SDN Live Screening Freshness
description: Verifies that OFAC SDN list screening uses live or recently-refreshed data (within 24 hours) rather than a stale snapshot committed to source control. OFAC additions and removals happen frequently; outdated lists generate both false negatives (screening misses real sanctions hits) and false positives (legitimate users flagged).
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OFAC:2024, FATF:2023:Rec.6
cwe: 1188
false_positive_rate: high
performance_class: fast
origin: OFAC enforcement actions consistently cite stale sanctions data as a control weakness; the list is updated multiple times per week.
PRESTON_META

echo "P-324: OFAC SDN Live Screening"

SRC="${SOURCE_DIR:-.}"

# Find OFAC references
ofac_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'OFAC|SDN[_-]list|sanctions[_-]list|sanctioned[_-]address|sanctions[_-]check|treasury[_-]gov|specially[_-]designated' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$ofac_refs" ]]; then
  record "WARN" "P-324 OFAC screening" "No OFAC/SDN screening references found in code" "$(echo "$ofac_refs" | head -10)"
  return 0 2>/dev/null || true
fi

# Look for live-fetch patterns
live_fetch=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" \
  -iE 'sanctions[_-]api|ofac[_-]api|treasury\.gov.*ofac.*xml|chainalysis.*sanctions|trm[_-]sanctions|refresh[_-]ofac|fetch[_-]sdn|update[_-]sanctions' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Look for snapshot files (anti-pattern: committed sanctions list)
snapshot=$(find "$SRC" \( -iname "sdn.xml" -o -iname "ofac*.csv" -o -iname "sanctions*.json" \) 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -n "$snapshot" ]] && [[ -z "$live_fetch" ]]; then
  count=$(echo "$snapshot" | wc -l | tr -d ' ')
  record "FAIL" "P-324 OFAC screening" "$count committed sanctions snapshot file(s) found without live-refresh code path" "$(echo "$snapshot" | head -10)"
elif [[ -n "$live_fetch" ]]; then
  count=$(echo "$live_fetch" | wc -l | tr -d ' ')
  record "PASS" "P-324 OFAC screening" "$count file(s) reference live OFAC/sanctions data refresh"
else
  record "WARN" "P-324 OFAC screening" "OFAC references present but no live-refresh mechanism detected; verify list freshness" "$(echo "$snapshot" | head -10)"
fi
