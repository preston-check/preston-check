#!/bin/bash
###############################################################################
# modules/smart-contract-audit/audit.sh
#
# Specialized runner for deep smart-contract security audit. Runs the
# Solidity-specific checks from the main catalog (P-301..P-310, P-348..P-353,
# P-356, P-510..P-517 for Solana/Move) plus the deep SC-specific checks in
# this module (P-700..P-719) plus optional integrations with Slither,
# Mythril, and Echidna when those tools are installed.
#
# Why a separate module?
#   - Smart-contract audits operate on different timescales (a single contract
#     gets weeks of audit attention; a fintech codebase gets minutes per scan)
#   - Different deliverable format (auditors write narrative reports, not
#     pass/fail tables — this module produces both)
#   - Optional heavyweight integrations (Slither symbolic execution can run
#     for hours; not appropriate for a CI scan)
#
# Usage:
#   modules/smart-contract-audit/audit.sh /path/to/contracts
#   modules/smart-contract-audit/audit.sh --slither --mythril /path/to/contracts
#   modules/smart-contract-audit/audit.sh --report sc-audit.md /path/to/contracts
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CONTRACTS_DIR=""
REPORT_FILE=""
RUN_SLITHER=false
RUN_MYTHRIL=false
RUN_ECHIDNA=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --report) REPORT_FILE="$2"; shift 2 ;;
    --slither) RUN_SLITHER=true; shift ;;
    --mythril) RUN_MYTHRIL=true; shift ;;
    --echidna) RUN_ECHIDNA=true; shift ;;
    --all) RUN_SLITHER=true; RUN_MYTHRIL=true; shift ;;
    --help|-h)
      sed -n '2,/^####/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) CONTRACTS_DIR="$1"; shift ;;
  esac
done

[[ -z "$CONTRACTS_DIR" ]] && { echo "usage: $0 [options] <contracts-dir>"; exit 1; }
[[ ! -d "$CONTRACTS_DIR" ]] && { echo "not a directory: $CONTRACTS_DIR"; exit 1; }

echo ""
echo "============================================================================"
echo "  PRESTON-CHECK SMART CONTRACT AUDIT MODULE"
echo "============================================================================"
echo "  Contracts:  $CONTRACTS_DIR"
echo "  Slither:    $($RUN_SLITHER && echo enabled || echo disabled)"
echo "  Mythril:    $($RUN_MYTHRIL && echo enabled || echo disabled)"
echo "  Echidna:    $($RUN_ECHIDNA && echo enabled || echo disabled)"
echo "============================================================================"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0
RESULTS=()

# Re-export record() locally
record() {
  local status="$1" check="$2" detail="$3" findings="${4:-}"
  case "$status" in
    PASS) ((PASS_COUNT++)); printf '\033[0;32m[%4s]\033[0m %-44s %s\n' "$status" "$check" "$detail" ;;
    FAIL) ((FAIL_COUNT++)); printf '\033[0;31m[%4s]\033[0m %-44s %s\n' "$status" "$check" "$detail" ;;
    WARN) ((WARN_COUNT++)); printf '\033[1;33m[%4s]\033[0m %-44s %s\n' "$status" "$check" "$detail" ;;
    SKIP) ((SKIP_COUNT++)); printf '\033[0;34m[%4s]\033[0m %-44s %s\n' "$status" "$check" "$detail" ;;
  esac
  RESULTS+=("$status|$check|$detail|$findings")
}
export -f record
export PASS_COUNT FAIL_COUNT WARN_COUNT SKIP_COUNT
export SOURCE_DIR="$CONTRACTS_DIR"

echo "── Phase 1: Solidity catalog checks (P-301..P-310, P-348..P-353, P-356)"
for n in 301 302 303 304 305 306 307 308 309 310 348 349 350 351 352 353 356; do
  for f in "$ROOT"/checks/${n}-*.sh; do
    [[ -f "$f" ]] && source "$f"
  done
done
echo ""

echo "── Phase 2: Deep smart-contract audit checks (P-700..P-719)"
for f in "$SCRIPT_DIR"/checks/*.sh; do
  [[ -f "$f" ]] && source "$f"
done
echo ""

echo "── Phase 3: Optional heavyweight integrations"
if $RUN_SLITHER; then
  bash "$SCRIPT_DIR/integrations/slither.sh" "$CONTRACTS_DIR" 2>&1 | sed 's/^/  /'
fi
if $RUN_MYTHRIL; then
  bash "$SCRIPT_DIR/integrations/mythril.sh" "$CONTRACTS_DIR" 2>&1 | sed 's/^/  /'
fi
if $RUN_ECHIDNA; then
  bash "$SCRIPT_DIR/integrations/echidna.sh" "$CONTRACTS_DIR" 2>&1 | sed 's/^/  /'
fi
echo ""

echo "============================================================================"
echo "  AUDIT SUMMARY"
echo "============================================================================"
TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))
SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$((PASS_COUNT * 100 / TOTAL))
echo "  Score: ${SCORE}%   PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  WARN: $WARN_COUNT  SKIP: $SKIP_COUNT"
echo "  Total checks: $TOTAL"

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo ""
  echo "  ⚠️  FAILs require resolution before deployment to production."
fi

if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# Smart Contract Audit Report"
    echo ""
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Contracts: $CONTRACTS_DIR"
    echo "Score: ${SCORE}%"
    echo ""
    echo "| Metric | Value |"
    echo "|---|---|"
    echo "| Total checks | $TOTAL |"
    echo "| PASS | $PASS_COUNT |"
    echo "| FAIL | $FAIL_COUNT |"
    echo "| WARN | $WARN_COUNT |"
    echo "| SKIP | $SKIP_COUNT |"
    echo ""
    echo "## Findings"
    echo ""
    echo "| Status | Check | Detail |"
    echo "|---|---|---|"
    for r in "${RESULTS[@]}"; do
      IFS='|' read -r status check detail _findings <<< "$r"
      [[ "$status" == "FAIL" || "$status" == "WARN" ]] && echo "| $status | $check | $detail |"
    done
  } > "$REPORT_FILE"
  echo ""
  echo "  Report saved to: $REPORT_FILE"
fi

[[ $FAIL_COUNT -gt 0 ]] && exit 1 || exit 0
