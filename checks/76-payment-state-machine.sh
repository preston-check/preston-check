#!/bin/bash
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
    record "WARN" "P-76 State machine" "$status_update status updates without state machine validation — invalid transitions possible"
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
  record "WARN" "P-76 Terminal states" "No terminal state protection — completed payments should not allow further status changes"
fi

# Check for expiration enforcement
expiration=$(grep -rn --include="*.java" --include="*.ts" \
  "expire\|expiration\|expires_on\|ttl.*payment\|timeout.*payment\|stale.*payment\|abandoned.*payment" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$expiration" ]]; then
  record "PASS" "P-76 Payment expiration" "Payment expiration enforcement found"
else
  record "WARN" "P-76 Payment expiration" "No payment expiration — pending payments should auto-expire"
fi
