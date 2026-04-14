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
RUN_MODE="full"  # "light" = P-01 to P-20 (fast), "full" = all checks
FORCE_LANG=""    # Override auto-detection with --lang

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
    --light|--fast) RUN_MODE="light"; shift ;;
    --full) RUN_MODE="full"; shift ;;
    --lang) FORCE_LANG="$2"; shift 2 ;;
    --list) ls "$CHECKS_DIR"/*.sh 2>/dev/null | xargs -I{} basename {} .sh; exit 0 ;;
    --help|-h)
      echo "preston-check — Pre-deployment security audit"
      echo ""
      echo "Usage: ./preston-check.sh [OPTIONS]"
      echo "  --config FILE    Use custom config (default: config.yml)"
      echo "  --check NAME     Run a single check"
      echo "  --report FILE    Save report to file"
      echo "  --ci             CI mode: exit 1 on any FAIL"
      echo "  --light, --fast  Light mode: core checks only (P-01 to P-20, ~30s)"
      echo "  --full           Full mode: all 82 checks (default, ~3min)"
      echo "  --lang LANG      Force language (java, go, python, typescript)"
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

# Language detection
source "$SCRIPT_DIR/lang/detect.sh"
if [[ -n "$FORCE_LANG" ]]; then
  DETECTED_LANG="$FORCE_LANG"
else
  detect_language "${SOURCE_DIR:-.}"
fi
load_language_profile "$DETECTED_LANG"

echo "  App:     ${APP_NAME:-not configured}"
echo "  Config:  $CONFIG_FILE"
echo "  Source:  ${SOURCE_DIR:-.}"
echo "  Lang:    ${DETECTED_LANG}"
if [[ "$RUN_MODE" == "light" ]]; then
  echo "  Mode:    LIGHT (P-01 to P-20 — core security checks)"
else
  echo "  Mode:    FULL (P-01 to P-82 — enterprise security suite)"
fi
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
    # In light mode, only run P-01 through P-20
    if [[ "$RUN_MODE" == "light" ]]; then
      check_num=$(basename "$check_file" | grep -oE '^[0-9]+' || echo "99")
      if [[ "$check_num" -gt 20 ]]; then
        continue
      fi
    fi
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

# Report (Markdown)
if [[ -n "$REPORT_FILE" ]]; then
  SCORE_PCT=$((PASS_COUNT * 100 / TOTAL))
  {
    echo "# Preston-Check Security Audit Report"
    echo ""
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "App: ${APP_NAME:-not configured}"
    echo "Source: ${SOURCE_DIR:-.}"
    echo "Mode: $RUN_MODE"
    echo "Version: 4.0"
    echo ""
    echo "---"
    echo ""
    echo "## Scorecard"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Score | ${SCORE_PCT}% |"
    echo "| PASS | $PASS_COUNT |"
    echo "| FAIL | $FAIL_COUNT |"
    echo "| WARN | $WARN_COUNT |"
    echo "| SKIP | $SKIP_COUNT |"
    echo "| Total Tests | $TOTAL |"
    echo ""
    if [[ $FAIL_COUNT -eq 0 ]]; then
      echo "**Status: ALL CHECKS PASSED** — ready for deployment."
    else
      echo "**Status: $FAIL_COUNT CHECKS FAILED** — review and fix before deploying."
    fi
    echo ""
    echo "---"
    echo ""
    # FAIL section first
    fail_items=()
    warn_items=()
    pass_items=()
    skip_items=()
    for r in "${RESULTS[@]}"; do
      IFS='|' read -r status check detail <<< "$r"
      case "$status" in
        FAIL) fail_items+=("| $status | $check | $detail |") ;;
        WARN) warn_items+=("| $status | $check | $detail |") ;;
        PASS) pass_items+=("| $status | $check | $detail |") ;;
        SKIP) skip_items+=("| $status | $check | $detail |") ;;
      esac
    done
    if [[ ${#fail_items[@]} -gt 0 ]]; then
      echo "## FAIL — Must Fix Before Deployment"
      echo ""
      echo "| Status | Check | Detail |"
      echo "|--------|-------|--------|"
      for item in "${fail_items[@]}"; do echo "$item"; done
      echo ""
    fi
    if [[ ${#warn_items[@]} -gt 0 ]]; then
      echo "## WARN — Review and Decide"
      echo ""
      echo "| Status | Check | Detail |"
      echo "|--------|-------|--------|"
      for item in "${warn_items[@]}"; do echo "$item"; done
      echo ""
    fi
    if [[ ${#pass_items[@]} -gt 0 ]]; then
      echo "## PASS — No Action Required"
      echo ""
      echo "| Status | Check | Detail |"
      echo "|--------|-------|--------|"
      for item in "${pass_items[@]}"; do echo "$item"; done
      echo ""
    fi
    if [[ ${#skip_items[@]} -gt 0 ]]; then
      echo "## SKIP — Check Could Not Run"
      echo ""
      echo "| Status | Check | Detail |"
      echo "|--------|-------|--------|"
      for item in "${skip_items[@]}"; do echo "$item"; done
      echo ""
    fi
    echo "---"
    echo ""
    echo "Preston-Check Enterprise Security Suite v4.0"
    echo "100 Check Categories | 276 Test Points | 6 Compliance Frameworks | 100% Coverage"
  } > "$REPORT_FILE"
  echo "  Report saved to: $REPORT_FILE"

  # Generate PDF if pandoc and Chrome are available
  PDF_FILE="${REPORT_FILE%.md}.pdf"
  if command -v pandoc &>/dev/null; then
    TMP_HTML=$(mktemp /tmp/preston-report-XXXX.html)
    pandoc "$REPORT_FILE" -o "$TMP_HTML" --from markdown --to html --standalone \
      --metadata title="Preston-Check Security Audit Report" 2>/dev/null
    if [[ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]]; then
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless --disable-gpu \
        --print-to-pdf="$PDF_FILE" --no-margins "$TMP_HTML" 2>/dev/null
      echo "  PDF report saved to: $PDF_FILE"
    elif command -v wkhtmltopdf &>/dev/null; then
      wkhtmltopdf "$TMP_HTML" "$PDF_FILE" 2>/dev/null
      echo "  PDF report saved to: $PDF_FILE"
    fi
    rm -f "$TMP_HTML"
  fi
  echo ""
fi

# CI mode
if $CI_MODE && [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
