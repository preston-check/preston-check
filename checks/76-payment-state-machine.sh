#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-76
name: Payment State Machine
description: Detects valid state transitions, terminal states, expiration policies.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-6
PRESTON_META


# P-76: Payment State Machine Integrity
# Every payment must follow a defined state machine with no skipped states.
# Invalid transitions (e.g., PENDING→PROCESSED skipping APPROVED) indicate bugs or exploitation.
echo "P-76: Payment State Machine"
SRC="${SOURCE_DIR:-.}"

# Check for state machine enforcement
state_machine=$(grep -rn --include="*.java" --include="*.ts" \
  "state.*machine\|status.*transition\|valid.*transition\|allowed.*status\|next.*state\|from.*to.*status\|transition.*map" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$state_machine" ]]; then
  record "PASS" "P-76 State machine" "Payment state machine/transition validation found"
else
  # Check if there are status updates without validation
  status_update=$(grep -rn --include="*.java" \
    "setStatus\|\.status.*=\|UPDATE.*SET.*status" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|migration\|CREATE\|ALTER" | wc -l | tr -d ' ')
  if [[ "$status_update" -gt 5 ]]; then
    record "WARN" "P-76 State machine" "$status_update status updates without state machine validation — invalid transitions possible" "$(echo "$status_update" | head -10)"
  else
    record "SKIP" "P-76 State machine" "Minimal status management found"
  fi
fi

# Check for terminal state protection (PROCESSED, SETTLED cannot be changed)
terminal_protect=$(grep -rn --include="*.java" --include="*.ts" \
  "terminal.*state\|final.*state\|cannot.*change\|immutable.*status\|already.*processed\|already.*settled\|already.*completed" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$terminal_protect" ]]; then
  record "PASS" "P-76 Terminal states" "Terminal state protection found"
else
  record "WARN" "P-76 Terminal states" "No terminal state protection — completed payments should not allow further status changes" "$(echo "$terminal_protect" | head -10)"
fi

# Check for expiration enforcement
expiration=$(grep -rn --include="*.java" --include="*.ts" \
  "expire\|expiration\|expires_on\|ttl.*payment\|timeout.*payment\|stale.*payment\|abandoned.*payment" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$expiration" ]]; then
  record "PASS" "P-76 Payment expiration" "Payment expiration enforcement found"
else
  record "WARN" "P-76 Payment expiration" "No payment expiration — pending payments should auto-expire" "$(echo "$expiration" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "state.*machine|status.*transition|valid.*transition|allowed.*status|next.*state|transition.*map|terminal.*state|final.*state|cannot.*change|immutable.*status|already.*processed|already.*settled|expire|expiration|ttl.*payment|timeout.*payment|stale.*payment" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-76 Payment state machine (Go)" "$_go_count pattern(s) found in Go code"
  else
    record "WARN" "P-76 Payment state machine (Go)" "No state machine/expiration patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "state.*machine|status.*transition|valid.*transition|allowed.*status|next.*state|transition.*map|terminal.*state|final.*state|cannot.*change|immutable.*status|already.*processed|already.*settled|expire|expiration|ttl.*payment|timeout.*payment|stale.*payment" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-76 Payment state machine (Rust)" "$_rs_count pattern(s) found in Rust code"
  else
    record "WARN" "P-76 Payment state machine (Rust)" "No state machine/expiration patterns found in Rust files"
  fi
fi
