#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-709
name: Governance Attack Vectors (Vote Buying, Single-Block Governance)
description: Detects governance contracts where voting power is computed at a single block (vulnerable to flash-loan-based vote buying) or where proposal execution lacks time-locks sufficient for the community to detect malicious proposals.
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.6.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC01
cwe: 269
false_positive_rate: medium
performance_class: fast
origin: Beanstalk Farms (April 2022, $182M) used flash-loan-acquired governance tokens to pass a malicious proposal in a single block; pattern recurs in DAOs with insufficient governance time-locks.
PRESTON_META

echo "P-709: Governance Attack Vectors"

SRC="${SOURCE_DIR:-.}"
gov=$(grep -rl --include="*.sol" -E 'function\s+(vote|propose|castVote|execute|queue)\s*\(' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$gov" ]]; then
  record "SKIP" "P-709 Governance attacks" "No governance functions detected"
  return 0 2>/dev/null || true
fi

# Check for snapshot-based voting (Compound's getPriorVotes pattern)
snapshot=$(grep -rln --include="*.sol" -E 'getPriorVotes|getPastVotes|checkpoint|snapshot|votingPowerAt|delegateBy.*block' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

# Time-lock evidence
timelock=$(grep -rln --include="*.sol" -E 'TimelockController|MIN_DELAY|GOVERNANCE_DELAY|onlyTimelock|delay\s*[><=]+\s*[0-9]+' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

g=$(echo "$gov" | wc -l | tr -d ' ')
s=$([[ -n "$snapshot" ]] && echo "$snapshot" | wc -l | tr -d ' ' || echo 0)
t=$([[ -n "$timelock" ]] && echo "$timelock" | wc -l | tr -d ' ' || echo 0)

if [[ ${s:-0} -gt 0 && ${t:-0} -gt 0 ]]; then
  record "PASS" "P-709 Governance attacks" "$g governance file(s); snapshot voting + time-lock both present"
elif [[ ${s:-0} -eq 0 ]]; then
  record "FAIL" "P-709 Governance attacks" "$g governance file(s) without snapshot/getPriorVotes — flash-loan vote-buying class" "$(echo "$gov" | head -10)"
else
  record "WARN" "P-709 Governance attacks" "$g governance file(s) with snapshot voting but no observable time-lock" "$(echo "$gov" | head -10)"
fi
