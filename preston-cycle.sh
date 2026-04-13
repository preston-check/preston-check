#!/bin/bash
###############################################################################
# preston-cycle — Virtuous Cycle Security Improvement Loop
#
# Each execution:
#   1. DIAGNOSE  — Run full Preston-check, capture results
#   2. ANALYZE   — Compare against previous cycle, identify delta
#   3. LEARN     — Record what improved, what regressed, what's new
#   4. PROPOSE   — Generate remediation plan for remaining issues
#   5. AWAIT     — Save plan for human review (DO NOT auto-apply)
#   6. (On approval) APPLY + DEPLOY + RE-CHECK
#
# Usage:
#   ./preston-cycle.sh --config configs/bloxcross.yml          # Run cycle
#   ./preston-cycle.sh --config configs/bloxcross.yml --history # Show history
#   ./preston-cycle.sh --config configs/bloxcross.yml --diff    # Compare to last
#
# The cycle log is stored at ~/DEV/preston-check/cycles/
# Each cycle gets a timestamped directory with:
#   - results.txt       Full Preston-check output
#   - summary.json      Machine-readable PASS/FAIL/WARN counts
#   - delta.md          What changed since last cycle
#   - remediation.md    Proposed fixes (for human review)
#   - approved.flag     Created when user approves (by Claude or manually)
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CYCLES_DIR="$SCRIPT_DIR/cycles"
CONFIG_FILE=""
SHOW_HISTORY=false
SHOW_DIFF=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --config) CONFIG_FILE="$2"; shift 2 ;;
    --history) SHOW_HISTORY=true; shift ;;
    --diff) SHOW_DIFF=true; shift ;;
    --help|-h)
      echo "preston-cycle — Virtuous Cycle Security Improvement Loop"
      echo ""
      echo "Usage: ./preston-cycle.sh --config configs/myapp.yml"
      echo "  --config FILE    Project config (required)"
      echo "  --history        Show improvement history"
      echo "  --diff           Compare to last cycle"
      echo "  --help           Show this help"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$CONFIG_FILE" ]]; then
  echo "Error: --config is required"
  echo "Usage: ./preston-cycle.sh --config configs/myapp.yml"
  exit 1
fi

APP_NAME=$(grep "^app_name:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo "unknown")
APP_CYCLES="$CYCLES_DIR/$APP_NAME"
mkdir -p "$APP_CYCLES"

# Get previous cycle (if any)
PREV_CYCLE=$(ls -1d "$APP_CYCLES"/cycle-* 2>/dev/null | tail -1)

# Show history
if $SHOW_HISTORY; then
  echo "============================================================================"
  echo "  PRESTON-CYCLE History: $APP_NAME"
  echo "============================================================================"
  echo ""
  for d in "$APP_CYCLES"/cycle-*; do
    [[ -d "$d" ]] || continue
    ts=$(basename "$d" | sed 's/cycle-//')
    if [[ -f "$d/summary.json" ]]; then
      pass=$(grep '"pass"' "$d/summary.json" | grep -oP '\d+')
      fail=$(grep '"fail"' "$d/summary.json" | grep -oP '\d+')
      warn=$(grep '"warn"' "$d/summary.json" | grep -oP '\d+')
      approved=""
      [[ -f "$d/approved.flag" ]] && approved=" [APPROVED]"
      echo "  $ts  PASS:$pass  FAIL:$fail  WARN:$warn$approved"
    fi
  done
  echo ""
  exit 0
fi

# Show diff
if $SHOW_DIFF; then
  if [[ -z "$PREV_CYCLE" ]]; then
    echo "No previous cycle to compare against."
    exit 0
  fi
  echo "============================================================================"
  echo "  DELTA from last cycle: $(basename "$PREV_CYCLE")"
  echo "============================================================================"
  cat "$PREV_CYCLE/delta.md" 2>/dev/null || echo "No delta file found"
  exit 0
fi

# ============================================================================
# STEP 1: DIAGNOSE
# ============================================================================

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
CYCLE_DIR="$APP_CYCLES/cycle-$TIMESTAMP"
mkdir -p "$CYCLE_DIR"

echo "============================================================================"
echo "  PRESTON-CYCLE #$(ls -1d "$APP_CYCLES"/cycle-* 2>/dev/null | wc -l | xargs)"
echo "  App: $APP_NAME"
echo "  Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Cycle dir: $CYCLE_DIR"
echo "============================================================================"
echo ""
echo "Step 1/4: DIAGNOSE — Running full Preston-check..."
echo ""

bash "$SCRIPT_DIR/preston-check.sh" --config "$CONFIG_FILE" --report "$CYCLE_DIR/report.md" 2>&1 | tee "$CYCLE_DIR/results.txt"

# Extract counts
PASS_COUNT=$(grep -c "\[PASS\]" "$CYCLE_DIR/results.txt" || echo 0)
FAIL_COUNT=$(grep -c "\[FAIL\]" "$CYCLE_DIR/results.txt" || echo 0)
WARN_COUNT=$(grep -c "\[WARN\]" "$CYCLE_DIR/results.txt" || echo 0)
SKIP_COUNT=$(grep -c "\[SKIP\]" "$CYCLE_DIR/results.txt" || echo 0)

cat > "$CYCLE_DIR/summary.json" << EOF
{
  "timestamp": "$TIMESTAMP",
  "app": "$APP_NAME",
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "warn": $WARN_COUNT,
  "skip": $SKIP_COUNT,
  "total": $((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT)),
  "score_pct": $(echo "scale=1; $PASS_COUNT * 100 / ($PASS_COUNT + $FAIL_COUNT + $WARN_COUNT + $SKIP_COUNT)" | bc 2>/dev/null || echo "0")
}
EOF

# ============================================================================
# STEP 2: ANALYZE — Compare against previous cycle
# ============================================================================

echo ""
echo "Step 2/4: ANALYZE — Comparing against previous cycle..."
echo ""

if [[ -n "$PREV_CYCLE" && -f "$PREV_CYCLE/summary.json" ]]; then
  PREV_PASS=$(grep '"pass"' "$PREV_CYCLE/summary.json" | grep -oP '\d+')
  PREV_FAIL=$(grep '"fail"' "$PREV_CYCLE/summary.json" | grep -oP '\d+')
  PREV_WARN=$(grep '"warn"' "$PREV_CYCLE/summary.json" | grep -oP '\d+')

  PASS_DELTA=$((PASS_COUNT - PREV_PASS))
  FAIL_DELTA=$((FAIL_COUNT - PREV_FAIL))
  WARN_DELTA=$((WARN_COUNT - PREV_WARN))

  # Find specific checks that changed
  PREV_FAILS=$(grep "\[FAIL\]" "$PREV_CYCLE/results.txt" 2>/dev/null | sed 's/.*\[FAIL\]//' | sort)
  CURR_FAILS=$(grep "\[FAIL\]" "$CYCLE_DIR/results.txt" | sed 's/.*\[FAIL\]//' | sort)

  FIXED=$(comm -23 <(echo "$PREV_FAILS") <(echo "$CURR_FAILS") 2>/dev/null)
  NEW_FAILS=$(comm -13 <(echo "$PREV_FAILS") <(echo "$CURR_FAILS") 2>/dev/null)

  cat > "$CYCLE_DIR/delta.md" << EOF
# Cycle Delta: $TIMESTAMP vs $(basename "$PREV_CYCLE")

## Score Change
| Metric | Previous | Current | Delta |
|--------|----------|---------|-------|
| PASS | $PREV_PASS | $PASS_COUNT | $([[ $PASS_DELTA -ge 0 ]] && echo "+")$PASS_DELTA |
| FAIL | $PREV_FAIL | $FAIL_COUNT | $([[ $FAIL_DELTA -ge 0 ]] && echo "+")$FAIL_DELTA |
| WARN | $PREV_WARN | $WARN_COUNT | $([[ $WARN_DELTA -ge 0 ]] && echo "+")$WARN_DELTA |

## Fixed (was FAIL, now PASS)
$(if [[ -n "$FIXED" ]]; then echo "$FIXED" | sed 's/^/- /'; else echo "None"; fi)

## New Failures (was not FAIL, now FAIL)
$(if [[ -n "$NEW_FAILS" ]]; then echo "$NEW_FAILS" | sed 's/^/- /'; else echo "None"; fi)

## Remaining Failures
$(echo "$CURR_FAILS" | sed 's/^/- /')
EOF

  cat "$CYCLE_DIR/delta.md"
else
  echo "  First cycle — no previous data to compare."
  cat > "$CYCLE_DIR/delta.md" << EOF
# First Cycle: $TIMESTAMP

Baseline established. No previous cycle to compare.

## Current State
- PASS: $PASS_COUNT
- FAIL: $FAIL_COUNT
- WARN: $WARN_COUNT
- SKIP: $SKIP_COUNT
EOF
fi

# ============================================================================
# STEP 3: LEARN — Extract lessons
# ============================================================================

echo ""
echo "Step 3/4: LEARN — Recording observations..."
echo ""

cat > "$CYCLE_DIR/lessons.md" << EOF
# Virtuous Cycle Lessons — Cycle $TIMESTAMP

## Loop 1: New Things Learned From Data & Executions

What did this cycle reveal that we didn't know before? These are insights
from the check results, delta analysis, and log patterns that should inform
future development practices.

### Observations
$(grep "\[FAIL\]" "$CYCLE_DIR/results.txt" | sed 's/.*\[FAIL\]/- FINDING:/' | head -10)
$(grep "\[WARN\]" "$CYCLE_DIR/results.txt" | sed 's/.*\[WARN\]/- OBSERVATION:/' | head -10)

### For Claude: Analyze the FAIL and WARN results above. For each one,
write a 1-2 sentence insight about what this tells us about the codebase
or development process that produced this result. What pattern or practice
led to this issue?

---

## Loop 2: New Potential Threats Detected

What new attack vectors, vulnerabilities, or risk patterns emerged in this cycle
that were not present in previous cycles? These should be added to the detection
rules and monitoring.

### New vs Previous
$(if [[ -n "$PREV_CYCLE" ]]; then
  PREV_FAILS=$(grep "\[FAIL\]\|\[WARN\]" "$PREV_CYCLE/results.txt" 2>/dev/null | sed 's/.*\[/[/' | sort)
  CURR_FAILS=$(grep "\[FAIL\]\|\[WARN\]" "$CYCLE_DIR/results.txt" | sed 's/.*\[/[/' | sort)
  NEW_ISSUES=$(comm -13 <(echo "$PREV_FAILS") <(echo "$CURR_FAILS") 2>/dev/null)
  if [[ -n "$NEW_ISSUES" ]]; then
    echo "NEW threats/issues not seen in previous cycle:"
    echo "$NEW_ISSUES" | sed 's/^/- /'
  else
    echo "No new threats — all current issues existed in the previous cycle."
  fi
else
  echo "First cycle — all findings are new baseline observations."
fi)

### For Claude: Review any NEW threats above. For each one, propose a new
Preston-Check rule or enhancement to an existing rule that would detect
this threat earlier in future cycles.

---

## Loop 3: What Worked Well — Expand and Implement Broadly

What security practices are working and should be replicated across the
entire codebase or to other modules?

### Strong Areas (consistent PASS)
$(grep "\[PASS\]" "$CYCLE_DIR/results.txt" | sed 's/.*\[PASS\]/- STRONG:/' | head -15)

### For Claude: Identify which PASS results represent practices that are
NOT yet applied universally. For example, if blacklist checks pass in
registration but are not present in other user-creation flows, recommend
expanding them. Propose specific locations where strong practices should
be replicated.

---

## Summary

| Loop | Count |
|------|-------|
| New learnings | $(grep "\[FAIL\]\|\[WARN\]" "$CYCLE_DIR/results.txt" | wc -l | xargs) findings to analyze |
| New threats | $(if [[ -n "$PREV_CYCLE" ]]; then comm -13 <(grep "\[FAIL\]\|\[WARN\]" "$PREV_CYCLE/results.txt" 2>/dev/null | sed 's/.*\[/[/' | sort) <(grep "\[FAIL\]\|\[WARN\]" "$CYCLE_DIR/results.txt" | sed 's/.*\[/[/' | sort) 2>/dev/null | wc -l | xargs; else echo "N/A (first cycle)"; fi) new issues |
| Strong practices | $(grep "\[PASS\]" "$CYCLE_DIR/results.txt" | wc -l | xargs) areas working well |
EOF

echo "  Lessons saved to: $CYCLE_DIR/lessons.md"

# ============================================================================
# STEP 4: PROPOSE — Generate remediation plan
# ============================================================================

echo ""
echo "Step 4/4: PROPOSE — Generating remediation plan..."
echo ""

cat > "$CYCLE_DIR/remediation.md" << EOF
# Remediation Plan — Cycle $TIMESTAMP

## Status: AWAITING APPROVAL

This plan was auto-generated by preston-cycle. Review and approve before
applying any changes. To approve, run:

  touch $CYCLE_DIR/approved.flag

Or tell Claude: "approve the latest preston-cycle for $APP_NAME"

## Failures to Fix

$(grep "\[FAIL\]" "$CYCLE_DIR/results.txt" | while read line; do
  check=$(echo "$line" | sed 's/.*\[FAIL\][[:space:]]*//' | cut -c1-40)
  detail=$(echo "$line" | sed 's/.*\[FAIL\][[:space:]]*//')
  echo "### $check"
  echo "$detail"
  echo ""
done)

## Warnings to Review (prioritized)

$(grep "\[WARN\]" "$CYCLE_DIR/results.txt" | while read line; do
  echo "- $(echo "$line" | sed 's/.*\[WARN\][[:space:]]*//')"
done)

## Recommended Next Actions

1. Fix all FAIL items (highest priority)
2. Review WARN items and decide which to fix vs accept
3. Re-run preston-cycle to verify improvements
4. Document accepted risks for WARN items that won't be fixed

## For Claude: Implementation Instructions

Read this file and the results.txt in the same directory. For each FAIL:
1. Identify the root cause by reading the check script in checks/
2. Find the affected source file
3. Propose a specific code change
4. Present to user for approval before applying
EOF

echo "  Remediation plan saved to: $CYCLE_DIR/remediation.md"

# ============================================================================
# STEP 5: PERSIST — Write to database for portal access
# ============================================================================

echo ""
echo "Step 5/5: PERSIST — Saving to database for portal..."

# Build JSON array of results
RESULTS_JSON="["
first=true
while IFS= read -r line; do
  status=$(echo "$line" | grep -oP '\[(PASS|FAIL|WARN|SKIP)\]' | tr -d '[]')
  detail=$(echo "$line" | sed 's/.*\]\s*//')
  if [[ -n "$status" ]]; then
    $first || RESULTS_JSON="$RESULTS_JSON,"
    first=false
    # Escape quotes in detail
    detail_escaped=$(echo "$detail" | sed 's/"/\\"/g')
    RESULTS_JSON="$RESULTS_JSON{\"status\":\"$status\",\"detail\":\"$detail_escaped\"}"
  fi
done < "$CYCLE_DIR/results.txt"
RESULTS_JSON="$RESULTS_JSON]"

DELTA_CONTENT=$(cat "$CYCLE_DIR/delta.md" 2>/dev/null | sed "s/'/''/g")
REMEDIATION_CONTENT=$(cat "$CYCLE_DIR/remediation.md" 2>/dev/null | sed "s/'/''/g")
LESSONS_CONTENT=$(cat "$CYCLE_DIR/lessons.md" 2>/dev/null | sed "s/'/''/g")
SCORE_PCT=$(echo "scale=1; $PASS_COUNT * 100 / ($PASS_COUNT + $FAIL_COUNT + $WARN_COUNT + $SKIP_COUNT)" | bc 2>/dev/null || echo "0")

# Try to write to bloxcross DB (if accessible)
DB_HOST_VAL=$(grep "^db_host:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs)
if [[ -n "$DB_HOST_VAL" ]]; then
  PGPASSWORD="${DB_PASSWORD:-}" psql -h "$DB_HOST_VAL" -U "${DB_USER:-bloxcross_user}" -d "${DB_DATABASE:-bloxcross}" -q 2>/dev/null << EOSQL || echo "  (DB write skipped — connection unavailable)"
INSERT INTO security_audit_cycle (app_name, pass_count, fail_count, warn_count, skip_count, score_pct, results, delta, remediation, lessons)
VALUES ('$APP_NAME', $PASS_COUNT, $FAIL_COUNT, $WARN_COUNT, $SKIP_COUNT, $SCORE_PCT, '$RESULTS_JSON'::jsonb,
        '$DELTA_CONTENT', '$REMEDIATION_CONTENT', '$LESSONS_CONTENT');
EOSQL
  echo "  Cycle saved to database"
fi

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo "============================================================================"
echo "  CYCLE COMPLETE"
echo "============================================================================"
echo ""
echo "  Score:  $PASS_COUNT PASS / $FAIL_COUNT FAIL / $WARN_COUNT WARN / $SKIP_COUNT SKIP"
echo "  Cycle:  $CYCLE_DIR"
echo "  Report: $CYCLE_DIR/report.md"
echo "  Delta:  $CYCLE_DIR/delta.md"
echo "  Plan:   $CYCLE_DIR/remediation.md"
echo ""
if [[ $FAIL_COUNT -eq 0 ]]; then
  echo "  ALL CHECKS PASSED — no remediation needed"
else
  echo "  Next steps:"
  echo "    1. Review: cat $CYCLE_DIR/remediation.md"
  echo "    2. Approve: touch $CYCLE_DIR/approved.flag"
  echo "    3. Ask Claude: \"Apply the approved preston-cycle remediation for $APP_NAME\""
  echo "    4. Re-run: ./preston-cycle.sh --config $CONFIG_FILE"
fi
echo ""
