#!/bin/bash
###############################################################################
# preston-check — Pre-deployment security audit tool
#
# Named after Preston Braswell, a hacker who created multiple fake accounts,
# bypassed 2FA, ran 21,201 automated session polling calls, and probed for
# race conditions and information leakage. This tool codifies the lessons
# learned from that attack into an automated, reusable security check.
#
# Usage:
#   ./preston-check.sh                          # Run all checks against local config
#   ./preston-check.sh --config myapp.yml       # Use custom config
#   ./preston-check.sh --check session-leak     # Run a single check
#   ./preston-check.sh --report report.md       # Save report to file
#   ./preston-check.sh --ci                     # CI mode: exit 1 on any FAIL
#
# Designed to be platform-agnostic. Configure via YAML or environment vars.
# Can be used for Blox, or any other fintech/API platform.
###############################################################################

set -uo pipefail
# Note: -e is intentionally NOT set because grep returns exit 1 on no match,
# which would abort the entire script. Individual checks handle errors internally.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKS_DIR="$SCRIPT_DIR/checks"
CONFIG_FILE="${PRESTON_CONFIG:-$SCRIPT_DIR/config.yml}"
REPORT_FILE=""
CI_MODE=false
SINGLE_CHECK=""
VERBOSE=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0
RESULTS=()

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --config) CONFIG_FILE="$2"; shift 2 ;;
    --check) SINGLE_CHECK="$2"; shift 2 ;;
    --report) REPORT_FILE="$2"; shift 2 ;;
    --ci) CI_MODE=true; shift ;;
    --verbose|-v) VERBOSE=true; shift ;;
    --list) ls "$CHECKS_DIR"/*.sh 2>/dev/null | xargs -I{} basename {} .sh; exit 0 ;;
    --help|-h)
      echo "preston-check — Pre-deployment security audit"
      echo ""
      echo "Usage: ./preston-check.sh [OPTIONS]"
      echo "  --config FILE    Use custom config (default: config.yml)"
      echo "  --check NAME     Run a single check"
      echo "  --report FILE    Save report to file"
      echo "  --ci             CI mode: exit 1 on any FAIL"
      echo "  --list           List available checks"
      echo "  --verbose        Show check details"
      echo "  --help           Show this help"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Load config
load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # Simple YAML parser for key: value pairs
    export APP_NAME=$(grep "^app_name:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo "unknown")
    export API_BASE_URL=$(grep "^api_base_url:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo "")
    export DB_HOST_CHECK=$(grep "^db_host:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo "")
    export LOG_DIR=$(grep "^log_dir:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo "")
    export SSH_HOST=$(grep "^ssh_host:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo "")
    export REDIS_HOST_CHECK=$(grep "^redis_host:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo "")
    export SOURCE_DIR=$(grep "^source_dir:" "$CONFIG_FILE" 2>/dev/null | cut -d: -f2- | xargs || echo ".")
  fi
}

# Result recording
record() {
  local status="$1"  # PASS, FAIL, WARN, SKIP
  local check="$2"
  local detail="$3"

  case $status in
    PASS) ((PASS_COUNT++)); color=$GREEN ;;
    FAIL) ((FAIL_COUNT++)); color=$RED ;;
    WARN) ((WARN_COUNT++)); color=$YELLOW ;;
    SKIP) ((SKIP_COUNT++)); color=$BLUE ;;
  esac

  printf "${color}[%4s]${NC} %-40s %s\n" "$status" "$check" "$detail"
  RESULTS+=("$status|$check|$detail")
}

# Export for use in check scripts
export -f record
export RED GREEN YELLOW BLUE NC

# Header
echo ""
echo "============================================================================"
echo "  PRESTON-CHECK — Pre-Deployment Security Audit"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================================"
echo ""

load_config
echo "  App:     ${APP_NAME:-not configured}"
echo "  Config:  $CONFIG_FILE"
echo "  Source:  ${SOURCE_DIR:-.}"
echo ""
echo "----------------------------------------------------------------------------"
echo ""

# Run checks
if [[ -n "$SINGLE_CHECK" ]]; then
  check_file="$CHECKS_DIR/${SINGLE_CHECK}.sh"
  if [[ -f "$check_file" ]]; then
    source "$check_file"
  else
    echo "Check not found: $SINGLE_CHECK"
    echo "Available checks:"
    ls "$CHECKS_DIR"/*.sh 2>/dev/null | xargs -I{} basename {} .sh
    exit 1
  fi
else
  for check_file in "$CHECKS_DIR"/*.sh; do
    [[ -f "$check_file" ]] || continue
    source "$check_file"
    echo ""
  done
fi

# Summary
echo ""
echo "============================================================================"
echo "  SUMMARY"
echo "============================================================================"
printf "  ${GREEN}PASS: %d${NC}  ${RED}FAIL: %d${NC}  ${YELLOW}WARN: %d${NC}  ${BLUE}SKIP: %d${NC}\n" \
  $PASS_COUNT $FAIL_COUNT $WARN_COUNT $SKIP_COUNT
echo ""

TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))
if [[ $FAIL_COUNT -eq 0 ]]; then
  printf "  ${GREEN}ALL CHECKS PASSED${NC} ($TOTAL checks run)\n"
else
  printf "  ${RED}$FAIL_COUNT CHECKS FAILED${NC} — review and fix before deploying\n"
fi
echo ""

# Report
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# Preston-Check Security Audit Report"
    echo ""
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "App: ${APP_NAME:-not configured}"
    echo "Source: ${SOURCE_DIR:-.}"
    echo ""
    echo "## Results"
    echo ""
    echo "| Status | Check | Detail |"
    echo "|--------|-------|--------|"
    for r in "${RESULTS[@]}"; do
      IFS='|' read -r status check detail <<< "$r"
      echo "| $status | $check | $detail |"
    done
    echo ""
    echo "## Summary"
    echo ""
    echo "PASS: $PASS_COUNT, FAIL: $FAIL_COUNT, WARN: $WARN_COUNT, SKIP: $SKIP_COUNT"
  } > "$REPORT_FILE"
  echo "  Report saved to: $REPORT_FILE"
  echo ""
fi

# CI mode
if $CI_MODE && [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
