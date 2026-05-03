#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-103
name: Double-Spend Race Conditions
description: Detects missing locking on financial mutations, concurrent withdrawal patterns.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.2.4, PCI-DSS:4.0:6.5.1, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-6, CIS-v8:16.10
PRESTON_META


###############################################################################
# P-103: Double-Spend, Overspend & Race Condition Prevention
#
# The most critical class of financial bugs. A double-spend occurs when the
# same funds are used in two concurrent transactions. An overspend occurs
# when a balance check passes but the debit races against another debit.
#
# Attack patterns:
#   1. TOCTOU (Time-Of-Check-Time-Of-Use): check balance → context switch →
#      another debit → original debit proceeds → negative balance
#   2. Concurrent identical requests: same idempotency key not enforced
#   3. Read-modify-write without locking: balance = getBalance() - amount
#   4. Budget bypass: check budget → concurrent spend → both pass
#   5. Replay: resubmit a completed payment request
#
# This check verifies that the codebase has the patterns needed to prevent
# these attacks across all six vulnerability categories.
###############################################################################
echo "P-103: Double-Spend & Race Conditions"
SRC="${SOURCE_DIR:-$1}"
SRC="${SRC:-.}"

# ═══════════════════════════════════════════════════════════════════════
# CHECK 1: Atomic balance debit (no read-modify-write)
# ═══════════════════════════════════════════════════════════════════════
# SAFE:   UPDATE wallet SET balance = balance - ? WHERE balance >= ?
# UNSAFE: balance = getBalance(); if (balance >= amount) setBalance(balance - amount);

if [[ "$DETECTED_LANG" == "java" ]]; then
  # Look for atomic SQL UPDATE with WHERE balance >= amount, or SELECT FOR UPDATE pattern
  atomic_debit=$(grep -rn --include="*.java" --include="*.sql" \
    -iE "balance\s*=\s*balance\s*-.*WHERE.*balance\s*>=|SET.*balance.*=.*balance.*-.*AND.*balance|ForUpdate|findPosition.*ForUpdate|SELECT.*FOR UPDATE.*withdraw|FOR UPDATE.*balance" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)

  # Look for UNSAFE read-modify-write pattern
  rmw_pattern=$(grep -rn --include="*.java" \
    -E 'setBalance.*getBalance|\.setBalance\(.*\.getBalance\(\)' \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|//\|/\*\|isBalance\|Available\|check\|boolean\|return" | head -5)

  if [[ -n "$atomic_debit" ]] && [[ -z "$rmw_pattern" ]]; then
    record "PASS" "P-103 Atomic debit" "Balance debits use atomic SQL (UPDATE WHERE balance >=) — no read-modify-write"
  elif [[ -n "$atomic_debit" ]] && [[ -n "$rmw_pattern" ]]; then
    count=$(echo "$rmw_pattern" | wc -l | tr -d ' ')
    record "FAIL" "P-103 Atomic debit" "$count read-modify-write patterns coexist with atomic debits — race condition risk"
    echo "$rmw_pattern" | head -3 | while read line; do echo "    $line"; done
  elif [[ -z "$atomic_debit" ]]; then
    record "FAIL" "P-103 Atomic debit" "No atomic balance debit found — balance updates must use UPDATE SET balance = balance - ? WHERE balance >= ?"
  fi

elif [[ "$DETECTED_LANG" == "go" ]]; then
  atomic_debit=$(grep -rn --include="*.go" --include="*.sql" \
    -iE "balance\s*=\s*balance\s*-.*WHERE.*balance\s*>=|UPDATE.*balance.*balance.*-" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|vendor\|_test\.go" | head -5)
  if [[ -n "$atomic_debit" ]]; then
    record "PASS" "P-103 Atomic debit" "Atomic balance debit found"
  else
    record "FAIL" "P-103 Atomic debit" "No atomic balance debit — use UPDATE SET balance = balance - ? WHERE balance >= ?"
  fi

elif [[ "$DETECTED_LANG" == "python" ]]; then
  atomic_debit=$(grep -rn --include="*.py" --include="*.sql" \
    -iE "F\(.*balance.*\)\s*-|balance\s*=\s*balance\s*-.*WHERE|update.*balance.*balance.*-" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|__pycache__\|venv" | head -5)
  if [[ -n "$atomic_debit" ]]; then
    record "PASS" "P-103 Atomic debit" "Atomic balance debit found (F() expression or raw SQL)"
  else
    record "WARN" "P-103 Atomic debit" "No atomic balance debit pattern found — verify no read-modify-write"
  fi
else
  record "WARN" "P-103 Atomic debit" "Check atomic debit patterns manually for $DETECTED_LANG"
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 2: Row-count verification on mutations
# ═══════════════════════════════════════════════════════════════════════
# The atomic UPDATE returns affected row count. If rows == 0, the WHERE
# condition failed (insufficient balance). Code MUST check this.
# SAFE:   int rows = debitBalance(...); if (rows != 1) throw ...
# UNSAFE: debitBalance(...); // void return, no check

if [[ "$DETECTED_LANG" == "java" ]]; then
  # Check for int return on @Modifying queries
  int_return=$(grep -rn --include="*.java" \
    -E "int (debit|credit|withdraw|transfer|spend|decrement|update)Balance|int (debit|withdraw|transfer)" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)

  void_return=$(grep -rn --include="*.java" \
    -E "void (debit|withdraw|transfer|spend|decrement)Balance|void (debit|withdraw|transfer)" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|//\|/\*\|domain\|dto\|set[A-Z]\|Event\|Notify\|Email\|SMS\|reverse_withdraw\|processPayment\|save" | head -5)

  if [[ -n "$int_return" ]] && [[ -z "$void_return" ]]; then
    record "PASS" "P-103 Row-count check" "Mutation queries return int row count — double-spend detected by rows != 1"
  elif [[ -n "$void_return" ]]; then
    count=$(echo "$void_return" | wc -l | tr -d ' ')
    record "FAIL" "P-103 Row-count check" "$count void-return mutations — must return int and check rows == 1"
    echo "$void_return" | head -3 | while read line; do echo "    $line"; done
  else
    record "WARN" "P-103 Row-count check" "No debit/withdraw mutation methods found — verify row count is checked"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 3: Pessimistic locking (SELECT FOR UPDATE)
# ═══════════════════════════════════════════════════════════════════════
# For complex operations that need to read-then-write, a SELECT FOR UPDATE
# prevents concurrent reads from seeing stale data.

for_update=$(grep -rn --include="*.java" --include="*.go" --include="*.py" --include="*.sql" \
  -iE "FOR UPDATE|FOR NO KEY UPDATE|pg_advisory_lock|advisory_lock|SELECT.*FOR UPDATE|findByIdForUpdate|LockModeType.PESSIMISTIC" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|node_modules\|_test\.go\|//\|/\*\|--" | head -5)

if [[ -n "$for_update" ]]; then
  count=$(echo "$for_update" | wc -l | tr -d ' ')
  record "PASS" "P-103 Pessimistic locking" "$count FOR UPDATE / advisory lock patterns for critical sections"
else
  record "WARN" "P-103 Pessimistic locking" "No SELECT FOR UPDATE or advisory locks — concurrent reads may see stale balances"
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 4: Concurrency control (semaphore, synchronized, mutex)
# ═══════════════════════════════════════════════════════════════════════
# Application-level concurrency control prevents multiple threads from
# processing the same entity simultaneously.

if [[ "$DETECTED_LANG" == "java" ]]; then
  # Check for semaphore/lock in files related to payments/wallets
  concurrency_files=$(find "$SRC" -name "*Payment*Service*.java" -o -name "*Wallet*Service*.java" -o -name "*Transfer*Service*.java" 2>/dev/null \
    | grep -v "test\|Test\|target")
  concurrency=""
  for cf in $concurrency_files; do
    hits=$(grep -n "Semaphore\|synchronized\|ReentrantLock\|\.lock()\|\.tryLock()\|MAX_CONCURRENT\|StampedLock" "$cf" 2>/dev/null | grep -v "import\|//\|/\*" | head -3)
    if [[ -n "$hits" ]]; then concurrency+="$cf: $hits"$'\n'; fi
  done
  # Also check broadly
  if [[ -z "$concurrency" ]]; then
    concurrency=$(grep -rln --include="*.java" "Semaphore\|ReentrantLock\|MAX_CONCURRENT" "$SRC" 2>/dev/null \
      | grep -iE "payment\|wallet\|transaction\|transfer" \
      | grep -v "test\|Test\|target" | head -5)
  fi
elif [[ "$DETECTED_LANG" == "go" ]]; then
  concurrency=$(grep -rn --include="*.go" \
    -E "sync\.Mutex|sync\.RWMutex|\.Lock\(\)|\.RLock\(\)|chan\s" \
    "$SRC" 2>/dev/null \
    | grep -iE "payment\|wallet\|transfer\|withdraw\|balance" \
    | grep -v "test\|Test\|vendor\|_test\.go" | head -5)
else
  concurrency=$(grep -rn --include="*.py" --include="*.ts" --include="*.rs" \
    -iE "lock\|mutex\|semaphore\|synchronized\|atomic" \
    "$SRC" 2>/dev/null \
    | grep -iE "payment\|wallet\|transfer\|withdraw\|balance" \
    | grep -v "test\|Test\|__pycache__\|node_modules\|target" | head -5)
fi

if [[ -n "$concurrency" ]]; then
  count=$(echo "$concurrency" | wc -l | tr -d ' ')
  record "PASS" "P-103 Concurrency control" "$count app-level concurrency guards (semaphore/lock/mutex) on financial operations"
else
  record "WARN" "P-103 Concurrency control" "No application-level concurrency control on financial operations — relies solely on DB"
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 5: Idempotency key on payment creation
# ═══════════════════════════════════════════════════════════════════════
# Every payment creation must accept an idempotency key. Retries with the
# same key must return the original result, not create a duplicate payment.

idempotency=$(grep -rn --include="*.java" --include="*.go" --include="*.py" --include="*.ts" \
  -iE "idempotency.key|idempotencyKey|Idempotency-Key|idempotent|X-Idempotency" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|node_modules\|_test\.go" | head -5)

idem_unique=$(grep -rn --include="*.java" --include="*.sql" \
  -iE "UNIQUE.*idempotency|idempotency.*UNIQUE|ON CONFLICT.*idempotency|findByIdempotencyKey" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|--" | head -5)

if [[ -n "$idempotency" ]] && [[ -n "$idem_unique" ]]; then
  record "PASS" "P-103 Idempotency key" "Idempotency key with uniqueness constraint — duplicate payments prevented"
elif [[ -n "$idempotency" ]]; then
  record "WARN" "P-103 Idempotency key" "Idempotency key accepted but no UNIQUE constraint — duplicates possible under race"
else
  record "FAIL" "P-103 Idempotency key" "No idempotency key on payment creation — retries create duplicate payments"
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 6: Budget enforcement atomicity
# ═══════════════════════════════════════════════════════════════════════
# Budget checks must be atomic with the spend. TOCTOU: check budget OK →
# concurrent spend → both pass → overspend.
# SAFE: UPDATE budget SET spent = spent + ? WHERE spent + ? <= limit
# UNSAFE: if (budget.getSpent() + amount <= limit) budget.setSpent(...)

if [[ "$DETECTED_LANG" == "java" ]]; then
  atomic_budget=$(grep -rn --include="*.java" --include="*.sql" \
    -iE "spend.*=.*spend.*\+.*WHERE.*spend.*<=|current_spend.*=.*current_spend.*\+.*WHERE|incrementSpendAtomic|atomic.*budget\|budget.*atomic" \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)

  rmw_budget=$(grep -rn --include="*.java" \
    -E 'getSpent\(\).*\+.*amount|getCurrentSpend\(\).*add|setSpent.*getSpent|setCurrentSpend.*getCurrent' \
    "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|//\|/\*\|atomic\|Atomic\|synchronized\|@Transactional" | head -5)

  if [[ -n "$atomic_budget" ]]; then
    record "PASS" "P-103 Atomic budget" "Budget enforcement uses atomic UPDATE (spend = spend + ? WHERE spend + ? <= limit)"
  elif [[ -n "$rmw_budget" ]]; then
    count=$(echo "$rmw_budget" | wc -l | tr -d ' ')
    record "FAIL" "P-103 Atomic budget" "$count read-modify-write budget patterns — concurrent spends bypass budget limits"
    echo "$rmw_budget" | head -3 | while read line; do echo "    $line"; done
  else
    record "WARN" "P-103 Atomic budget" "No budget enforcement pattern detected — verify budget checks are atomic"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 7: Transaction isolation level
# ═══════════════════════════════════════════════════════════════════════
# Financial operations should use SERIALIZABLE or at minimum REPEATABLE READ.
# READ COMMITTED allows phantom reads during multi-step operations.

isolation=$(grep -rn --include="*.java" --include="*.go" --include="*.py" --include="*.yml" --include="*.yaml" --include="*.properties" \
  -iE "SERIALIZABLE|REPEATABLE.READ|isolation.*level|@Transactional.*isolation|transaction-isolation" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|node_modules\|//\|/\*\|--" | head -5)

if [[ -n "$isolation" ]]; then
  record "PASS" "P-103 Transaction isolation" "Explicit transaction isolation level configured"
else
  record "WARN" "P-103 Transaction isolation" "No explicit isolation level — defaults to READ COMMITTED which allows phantom reads in multi-step operations"
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 8: Payment status terminal states
# ═══════════════════════════════════════════════════════════════════════
# Completed/failed payments must not be modifiable. Replay attacks
# re-execute a completed payment if status isn't checked.

if [[ "$DETECTED_LANG" == "java" ]]; then
  status_check=$(grep -rn --include="*.java" \
    -E 'status.*COMPLETED\|status.*FAILED\|status.*SETTLED|isTerminal|isFinal|COMPLETED.*throw|FAILED.*throw|already.*completed|already.*processed' \
    "$SRC" 2>/dev/null \
    | grep -iE "payment\|transaction\|transfer" \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)
  if [[ -n "$status_check" ]]; then
    record "PASS" "P-103 Terminal state guard" "Completed/failed payments reject re-processing — replay attack prevented"
  else
    record "WARN" "P-103 Terminal state guard" "No terminal state guard found on payments — completed transactions may be re-executed"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 9: Negative balance detection
# ═══════════════════════════════════════════════════════════════════════
# Even with atomic debits, bugs happen. A reconciliation check should
# detect if any wallet has a negative balance.

negative_detect=$(grep -rn --include="*.java" --include="*.go" --include="*.py" --include="*.sql" \
  -iE "balance\s*<\s*0|negative.*balance|balance.*negative|WHERE.*balance.*<.*0|check.*negative|mismatch.*balance" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|node_modules\|_test\.go" | head -5)

if [[ -n "$negative_detect" ]]; then
  record "PASS" "P-103 Negative balance detection" "Negative balance detection/reconciliation found"
else
  record "WARN" "P-103 Negative balance detection" "No negative balance detection — add periodic reconciliation to catch double-spend outcomes"
fi

# ═══════════════════════════════════════════════════════════════════════
# CHECK 10: Concurrent request deduplication
# ═══════════════════════════════════════════════════════════════════════
# Multiple identical requests arriving within milliseconds (network retry,
# user double-click, attacker replay). Must be deduplicated.

if [[ "$DETECTED_LANG" == "java" ]]; then
  dedup=$(grep -rn --include="*.java" \
    -E 'ConcurrentHashMap|processedIds|deduplication|deduplicate|alreadyProcessed|recentRequests|requestCache' \
    "$SRC" 2>/dev/null \
    | grep -iE "payment\|request\|webhook\|message\|event\|transaction" \
    | grep -v "test\|Test\|target\|//\|/\*" | head -5)
  if [[ -n "$dedup" ]]; then
    count=$(echo "$dedup" | wc -l | tr -d ' ')
    record "PASS" "P-103 Request deduplication" "$count deduplication patterns — concurrent identical requests handled"
  else
    record "WARN" "P-103 Request deduplication" "No request deduplication found — duplicate requests may create duplicate transactions"
  fi
fi
