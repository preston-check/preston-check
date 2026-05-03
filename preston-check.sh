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
AIRGAP_MODE=false              # --airgap: forbid all network calls (telemetry, etc.)
TELEMETRY_OPT_IN_FLAG=false    # --telemetry-opt-in: anonymous score reporting
INCLUDE_PROPOSED=false         # --include-proposed: run unreviewed community checks
CI_SOFT_MODE=false             # --ci-soft: never exit 1 (CI handles its own thresholds)
FRAMEWORK_FILTER=""            # --framework FILTER: only run checks whose metadata frameworks contain FILTER
CATEGORY_FILTER=""             # --category VAL[,VAL...]: filter by metadata category
PRESTON_VERSION="1.2.1"

export AIRGAP_MODE PRESTON_VERSION

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
    --airgap) AIRGAP_MODE=true; export AIRGAP_MODE; shift ;;
    --telemetry-opt-in) TELEMETRY_OPT_IN_FLAG=true; shift ;;
    --include-proposed) INCLUDE_PROPOSED=true; shift ;;
    --ci-soft) CI_SOFT_MODE=true; shift ;;
    --framework) FRAMEWORK_FILTER="$2"; shift 2 ;;
    --category) CATEGORY_FILTER="$2"; shift 2 ;;
    --code-only) CATEGORY_FILTER="code-scan"; shift ;;
    --docs-only) CATEGORY_FILTER="compliance-evidence"; shift ;;
    --infra-only) CATEGORY_FILTER="infra-scan"; shift ;;
    --live-only) CATEGORY_FILTER="live-monitoring"; shift ;;
    --list)
      for d in "$CHECKS_DIR" "$CHECKS_DIR/core" "$CHECKS_DIR/community/verified" "$CHECKS_DIR/community/accepted" "$CHECKS_DIR/community/proposed"; do
        [[ -d "$d" ]] && ls "$d"/*.sh 2>/dev/null | xargs -I{} basename {} .sh
      done
      exit 0 ;;
    --help|-h)
      echo "preston-check — Pre-deployment security audit"
      echo ""
      echo "Usage: ./preston-check.sh [OPTIONS]"
      echo "  --config FILE    Use custom config (default: config.yml)"
      echo "  --check NAME     Run a single check"
      echo "  --report FILE    Save report to file"
      echo "  --ci                 CI mode: exit 1 on any FAIL"
      echo "  --ci-soft            CI mode that never exits 1 (caller applies thresholds)"
      echo "  --light, --fast      Light mode: P-01 to P-20 only (~30s)"
      echo "  --full               Full mode: all checks (default, ~3min)"
      echo "  --lang LANG          Force language (java, go, python, typescript)"
      echo "  --airgap             No network calls. Disables telemetry."
      echo "  --telemetry-opt-in   Send anonymous score to State of Fintech Security report"
      echo "  --include-proposed   Run unreviewed community-contributed checks"
      echo "  --framework NAME     Run only checks whose metadata references NAME"
      echo "                       (e.g., MiCA, CCSS:9.0:Level2, OWASP-SC-Top-10:2025, FATF, OFAC, DORA)"
      echo "  --category VAL       Filter by metadata category (comma-separated for multiple)"
      echo "                       Values: code-scan, compliance-evidence, live-monitoring, infra-scan"
      echo "  --code-only          Alias: --category code-scan (pure source-code analysis)"
      echo "  --docs-only          Alias: --category compliance-evidence (policy/evidence verification)"
      echo "  --infra-only         Alias: --category infra-scan"
      echo "  --live-only          Alias: --category live-monitoring (SSH-based prod log checks)"
      echo "  --list               List available checks"
      echo "  --verbose            Show check details"
      echo "  --help               Show this help"
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

# Source product modules (license, metadata, telemetry, branding, oss detection)
# These are intentionally sourced AFTER load_config sets SOURCE_DIR, but BEFORE
# check execution so tier and brand context are established.
[[ -f "$SCRIPT_DIR/lib/check_metadata.sh" ]] && source "$SCRIPT_DIR/lib/check_metadata.sh"
[[ -f "$SCRIPT_DIR/lib/license.sh" ]]        && source "$SCRIPT_DIR/lib/license.sh"
[[ -f "$SCRIPT_DIR/lib/telemetry.sh" ]]      && source "$SCRIPT_DIR/lib/telemetry.sh"
[[ -f "$SCRIPT_DIR/lib/branding.sh" ]]       && source "$SCRIPT_DIR/lib/branding.sh"
[[ -f "$SCRIPT_DIR/lib/oss_detection.sh" ]]  && source "$SCRIPT_DIR/lib/oss_detection.sh"

# Honor --telemetry-opt-in flag
if [[ "$TELEMETRY_OPT_IN_FLAG" == "true" ]]; then
  TELEMETRY_OPT_IN="true"
fi
# Airgap forces telemetry off
if [[ "$AIRGAP_MODE" == "true" ]]; then
  TELEMETRY_OPT_IN="false"
fi

load_config

# Load license, detect OSS exemption, apply branding (Enterprise only)
if declare -f load_license >/dev/null; then load_license; fi
if declare -f detect_oss_license >/dev/null; then detect_oss_license "${SOURCE_DIR:-.}"; fi
if declare -f apply_brand_config >/dev/null; then apply_brand_config "$CONFIG_FILE"; fi

# Effective tier accounts for OSS exemption
EFFECTIVE_TIER="${LICENSE_TIER:-free}"
if declare -f effective_tier >/dev/null; then
  EFFECTIVE_TIER="$(effective_tier "$LICENSE_TIER")"
fi

# Header
echo ""
echo "============================================================================"
echo "  ${BRAND_NAME:-Preston-Check} — Pre-Deployment Security Audit"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================================"
echo ""

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
echo "  Lang:    ${DETECTED_LANG} (primary) | ${DETECTED_LANGS}"
if [[ "$RUN_MODE" == "light" ]]; then
  echo "  Mode:    LIGHT (P-01 to P-20 — core security checks)"
else
  echo "  Mode:    FULL (all enterprise security checks)"
fi
declare -f print_license_status   >/dev/null && print_license_status
declare -f print_oss_status       >/dev/null && print_oss_status
declare -f print_telemetry_status >/dev/null && print_telemetry_status
[[ "$AIRGAP_MODE" == "true" ]] && echo "  Airgap:  ON (no network calls)"
[[ "$EFFECTIVE_TIER" != "${LICENSE_TIER:-free}" ]] && echo "  Effective tier: $EFFECTIVE_TIER (OSS exemption)"
echo ""
echo "----------------------------------------------------------------------------"
echo ""

# Build list of check directories to scan, in priority order.
# checks/         legacy root (treated as core for backward compatibility)
# checks/core/    canonical maintainer-authored
# checks/community/verified/  promoted community checks
# checks/community/accepted/  reviewed community checks
# checks/community/proposed/  unreviewed; only with --include-proposed
CHECK_DIRS=("$CHECKS_DIR")
[[ -d "$CHECKS_DIR/core" ]] && CHECK_DIRS+=("$CHECKS_DIR/core")
[[ -d "$CHECKS_DIR/community/verified" ]] && CHECK_DIRS+=("$CHECKS_DIR/community/verified")
[[ -d "$CHECKS_DIR/community/accepted" ]] && CHECK_DIRS+=("$CHECKS_DIR/community/accepted")
if [[ "$INCLUDE_PROPOSED" == "true" && -d "$CHECKS_DIR/community/proposed" ]]; then
  CHECK_DIRS+=("$CHECKS_DIR/community/proposed")
fi

# Decide whether a single check should run, based on metadata + tier + framework filter
should_run_check() {
  local check_file="$1"
  if declare -f parse_check_metadata >/dev/null; then
    parse_check_metadata "$check_file"
    if [[ -n "${META_MIN_TIER:-}" ]] && declare -f tier_allows_check >/dev/null; then
      if ! tier_allows_check "$META_MIN_TIER" "$EFFECTIVE_TIER"; then
        return 1
      fi
    fi
    if [[ -n "$FRAMEWORK_FILTER" ]]; then
      if [[ -z "${META_FRAMEWORKS:-}" ]] || ! echo "${META_FRAMEWORKS}" | grep -qiE "$(echo "$FRAMEWORK_FILTER" | sed 's/[][\.*^$/]/\\&/g')"; then
        return 1
      fi
    fi
    if [[ -n "$CATEGORY_FILTER" ]]; then
      local matched=false _cat
      local _cur="${META_CATEGORY:-}"
      IFS=',' read -ra _cats <<< "$CATEGORY_FILTER"
      for _cat in "${_cats[@]}"; do
        _cat="${_cat## }"; _cat="${_cat%% }"
        if [[ "$_cur" == "$_cat" ]]; then matched=true; break; fi
      done
      [[ "$matched" == "true" ]] || return 1
    fi
  fi
  return 0
}

# Run checks
if [[ -n "$SINGLE_CHECK" ]]; then
  found=""
  for d in "${CHECK_DIRS[@]}"; do
    if [[ -f "$d/${SINGLE_CHECK}.sh" ]]; then found="$d/${SINGLE_CHECK}.sh"; break; fi
  done
  if [[ -n "$found" ]]; then
    if should_run_check "$found"; then
      source "$found"
    else
      echo "Check $SINGLE_CHECK is gated to a higher tier than your current license ($EFFECTIVE_TIER)."
      exit 2
    fi
  else
    echo "Check not found: $SINGLE_CHECK"
    echo "Available checks:"
    for d in "${CHECK_DIRS[@]}"; do ls "$d"/*.sh 2>/dev/null | xargs -I{} basename {} .sh; done
    exit 1
  fi
else
  for d in "${CHECK_DIRS[@]}"; do
    for check_file in "$d"/*.sh; do
      [[ -f "$check_file" ]] || continue
      # In light mode, only run P-01 through P-20
      if [[ "$RUN_MODE" == "light" ]]; then
        check_num=$(basename "$check_file" | grep -oE '^[0-9]+' || echo "99")
        if [[ "$check_num" -gt 20 ]]; then
          continue
        fi
      fi
      if ! should_run_check "$check_file"; then
        # Silently skip checks that are above the user's effective tier.
        # In verbose mode, surface them as SKIP entries.
        if [[ "$VERBOSE" == "true" ]]; then
          record "SKIP" "${META_ID:-?} ${META_NAME:-$(basename "$check_file" .sh)}" "Requires $META_MIN_TIER tier (current: $EFFECTIVE_TIER)"
        fi
        continue
      fi
      source "$check_file"
      echo ""
    done
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
  if [[ $TOTAL -gt 0 ]]; then
    SCORE_PCT=$((PASS_COUNT * 100 / TOTAL))
  else
    SCORE_PCT=0
  fi
  {
    echo "# ${BRAND_NAME:-Preston-Check} Security Audit Report"
    echo ""
    [[ -n "${BRAND_LOGO_URL:-}" ]] && echo "![logo](${BRAND_LOGO_URL})"
    [[ -n "${BRAND_LOGO_URL:-}" ]] && echo ""
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "App: ${APP_NAME:-not configured}"
    echo "Source: ${SOURCE_DIR:-.}"
    echo "Mode: $RUN_MODE"
    echo "Tier: ${EFFECTIVE_TIER:-free}"
    [[ -n "${LICENSE_CUSTOMER:-}" ]] && echo "Customer: $LICENSE_CUSTOMER"
    [[ -n "${LICENSE_WARNING:-}" ]] && echo "Renewal: $LICENSE_WARNING"
    echo "Version: ${PRESTON_VERSION:-1.0.0}"
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
    echo "${BRAND_FOOTER:-Preston-Check Enterprise Security Suite}"
    echo ""
    if [[ -n "${LICENSE_CUSTOMER:-}" && "${BRAND_NAME:-Preston-Check}" != "Preston-Check" ]]; then
      echo "Powered by Preston-Check · https://preston-check.dev"
    fi
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

# Send opt-in anonymous telemetry (no-op unless explicitly opted in and not airgapped)
if declare -f send_telemetry >/dev/null; then
  send_telemetry "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT" "$SKIP_COUNT" "$TOTAL" "${DETECTED_LANG:-unknown}"
fi

# CI mode
if $CI_SOFT_MODE; then
  exit 0
fi
if $CI_MODE && [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
