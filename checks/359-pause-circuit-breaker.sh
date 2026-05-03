#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-359
name: Emergency Pause / Circuit Breaker Pattern
description: Verifies smart contracts handling user funds expose a pause / circuit breaker mechanism so the team can halt operations when an exploit is in progress. Many exploits drain funds over multiple transactions and could be partially mitigated by a fast pause, but only if the pause exists.
category: code-scan
severity: medium
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:RS.MI
cwe: 754
false_positive_rate: high
performance_class: fast
origin: Multiple DeFi exploits (Cream Finance, Beanstalk, Mango Markets) drained funds over the course of minutes; protocols with pause mechanisms saved residual TVL by halting operations during the attack.
PRESTON_META

echo "P-359: Emergency Pause / Circuit Breaker"

SRC="${SOURCE_DIR:-.}"

# Find user-funds-handling contracts
funds_files=$(grep -rl --include="*.sol" \
  -E 'function\s+(deposit|withdraw|swap|trade|borrow|lend|stake)' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$funds_files" ]]; then
  record "SKIP" "P-359 Pause / breaker" "No user-funds contracts detected"
  return 0 2>/dev/null || true
fi

unprotected=0
total=0
for f in $funds_files; do
  ((total++))
  if ! grep -qE 'whenNotPaused|Pausable|paused\(\)|emergencyShutdown|_pause\(|circuitBreaker|emergency[_-]stop|haltOperations' "$f" 2>/dev/null; then
    ((unprotected++))
  fi
done

if [[ $unprotected -eq 0 ]]; then
  record "PASS" "P-359 Pause / breaker" "$total user-funds contract(s) all reference pause / circuit-breaker patterns"
else
  record "WARN" "P-359 Pause / breaker" "$unprotected of $total user-funds contract(s) lack visible pause / circuit-breaker mechanism" "$(echo "$funds_files" | head -10)"
fi
