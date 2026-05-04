#!/bin/bash
###############################################################################
# preston-check — Pre-deployment security audit tool
#
# Named after Preston X, a hacker who created multiple fake accounts,
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
AI_AUGMENT=false               # --ai-augment: add AI false-positive filter + explanations
AI_FIX=false                   # --ai-fix: also generate suggested patches per finding
INCLUDE_PROPOSED=false         # --include-proposed: run unreviewed community checks
CI_SOFT_MODE=false             # --ci-soft: never exit 1 (CI handles its own thresholds)
FRAMEWORK_FILTER=""            # --framework FILTER: only run checks whose metadata frameworks contain FILTER
CATEGORY_FILTER=""             # --category VAL[,VAL...]: filter by metadata category
SEVERITY_FILTER=""             # --severity VAL[,VAL...]: filter by severity
PRESTON_VERSION="1.7.7"

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
    --ai-augment) AI_AUGMENT=true; export AI_AUGMENT; shift ;;
    --ai-fix) AI_FIX=true; AI_AUGMENT=true; export AI_FIX AI_AUGMENT; shift ;;
    --include-proposed) INCLUDE_PROPOSED=true; shift ;;
    --version|-V) echo "preston-check $PRESTON_VERSION"; exit 0 ;;
    --ci-soft) CI_SOFT_MODE=true; shift ;;
    --framework) FRAMEWORK_FILTER="$2"; shift 2 ;;
    --category) CATEGORY_FILTER="$2"; shift 2 ;;
    --code-only) CATEGORY_FILTER="code-scan"; shift ;;
    --docs-only) CATEGORY_FILTER="compliance-evidence"; shift ;;
    --infra-only) CATEGORY_FILTER="infra-scan"; shift ;;
    --live-only) CATEGORY_FILTER="live-monitoring"; shift ;;
    --severity) SEVERITY_FILTER="$2"; shift 2 ;;
    --critical-only) SEVERITY_FILTER="critical"; shift ;;
    --high-and-up) SEVERITY_FILTER="critical,high"; shift ;;
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
      echo "  --airgap             No network calls. Disables telemetry and AI."
      echo "  --telemetry-opt-in   Send anonymous score to State of Fintech Security report"
      echo "  --ai-augment         Add AI false-positive filter + explanations to FAIL/WARN findings"
      echo "  --ai-fix             Also generate suggested patches per finding (implies --ai-augment)"
      echo "  --include-proposed   Run unreviewed community-contributed checks"
      echo "  --framework NAME     Run only checks whose metadata references NAME"
      echo "                       (e.g., MiCA, CCSS:9.0:Level2, OWASP-SC-Top-10:2025, FATF, OFAC, DORA)"
      echo "  --category VAL       Filter by metadata category (comma-separated for multiple)"
      echo "                       Values: code-scan, compliance-evidence, live-monitoring, infra-scan"
      echo "  --code-only          Alias: --category code-scan (pure source-code analysis)"
      echo "  --docs-only          Alias: --category compliance-evidence (policy/evidence verification)"
      echo "  --infra-only         Alias: --category infra-scan"
      echo "  --live-only          Alias: --category live-monitoring (SSH-based prod log checks)"
      echo "  --severity VAL       Filter by severity (comma-separated): critical, high, medium, low, info"
      echo "  --critical-only      Alias: --severity critical (fast core run, blocking issues only)"
      echo "  --high-and-up        Alias: --severity critical,high (CI-blocking severity)"
      echo "  --list               List available checks"
      echo "  --verbose            Show check details"
      echo "  --version, -V        Print version and exit"
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

# Result recording. Supports an optional 4th argument carrying multi-line
# `file:line:content` findings; those are surfaced in the markdown report
# under each FAIL/WARN row, and printed to the terminal in --verbose mode.
record() {
  local status="$1"  # PASS, FAIL, WARN, SKIP
  local check="$2"
  local detail="$3"
  local findings="${4:-}"

  case $status in
    PASS) ((PASS_COUNT++)); color=$GREEN ;;
    FAIL) ((FAIL_COUNT++)); color=$RED ;;
    WARN) ((WARN_COUNT++)); color=$YELLOW ;;
    SKIP) ((SKIP_COUNT++)); color=$BLUE ;;
  esac

  printf "${color}[%4s]${NC} %-40s %s\n" "$status" "$check" "$detail"

  # Always show first findings inline for FAIL/WARN; show all in --verbose.
  if [[ -n "$findings" ]]; then
    if [[ "$VERBOSE" == "true" || "$status" == "FAIL" ]]; then
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf "         %s\n" "$line"
      done <<< "$(echo "$findings" | head -10)"
    fi
  fi

  # Encode findings with newlines escaped so the pipe-delimited RESULTS
  # array can roundtrip multi-line data safely.
  local findings_enc=""
  if [[ -n "$findings" ]]; then
    findings_enc="$(printf '%s' "$findings" | tr '\n|' '\036\037')"
  fi
  RESULTS+=("$status|$check|$detail|$findings_enc")
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
[[ -f "$SCRIPT_DIR/lib/ai_analyze.sh" ]]     && source "$SCRIPT_DIR/lib/ai_analyze.sh"
[[ -f "$SCRIPT_DIR/lib/ai_autofix.sh" ]]     && source "$SCRIPT_DIR/lib/ai_autofix.sh"

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
    if [[ -n "$SEVERITY_FILTER" ]]; then
      local sev_match=false _sev
      local _cur_sev="${META_SEVERITY:-}"
      IFS=',' read -ra _sevs <<< "$SEVERITY_FILTER"
      for _sev in "${_sevs[@]}"; do
        _sev="${_sev## }"; _sev="${_sev%% }"
        if [[ "$_cur_sev" == "$_sev" ]]; then sev_match=true; break; fi
      done
      [[ "$sev_match" == "true" ]] || return 1
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
        # Strip leading zeros so bash doesn't try to parse "08"/"09" as octal.
        check_num=$(basename "$check_file" | grep -oE '^[0-9]+' || echo "99")
        check_num="${check_num#"${check_num%%[!0]*}"}"
        : "${check_num:=0}"
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
    [[ -n "$FRAMEWORK_FILTER" ]] && echo "Framework: $FRAMEWORK_FILTER"
    [[ -n "$CATEGORY_FILTER"  ]] && echo "Category: $CATEGORY_FILTER"
    [[ -n "$SEVERITY_FILTER"  ]] && echo "Severity: $SEVERITY_FILTER"
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
    # Section assembly: build per-status lists, then emit tables and per-row
    # findings under each FAIL/WARN entry.
    fail_items=()
    warn_items=()
    pass_items=()
    skip_items=()
    fail_findings=()
    warn_findings=()
    for r in "${RESULTS[@]}"; do
      IFS='|' read -r status check detail findings_enc <<< "$r"
      case "$status" in
        FAIL)
          fail_items+=("| $status | $check | $detail |")
          fail_findings+=("$check|$findings_enc")
          ;;
        WARN)
          warn_items+=("| $status | $check | $detail |")
          warn_findings+=("$check|$findings_enc")
          ;;
        PASS) pass_items+=("| $status | $check | $detail |") ;;
        SKIP) skip_items+=("| $status | $check | $detail |") ;;
      esac
    done

    # Emit findings under a section heading. RESULT entries store findings
    # with newlines escaped as \036 and pipes as \037; decode for display.
    # When --ai-augment / --ai-fix is on, also append per-finding AI analysis
    # and (optionally) a suggested patch.
    emit_findings_block() {
      local check="$1" findings_enc="$2"
      [[ -z "$findings_enc" ]] && return 0
      local decoded
      decoded="$(printf '%s' "$findings_enc" | tr '\036\037' '\n|')"
      [[ -z "$decoded" ]] && return 0
      echo "#### $check — findings"
      echo ""
      echo '```'
      echo "$decoded"
      echo '```'
      echo ""

      # AI augmentation: per-finding analysis and (optional) suggested patch.
      # Each finding is its own LLM call, with per-finding caching so reruns
      # over the same code don't re-bill.
      if declare -f ai_is_available >/dev/null 2>&1 && ai_is_available; then
        local check_id check_name
        check_id="$(echo "$check" | awk '{print $1}')"
        check_name="$(echo "$check" | cut -d' ' -f2-)"
        local i=0
        while IFS= read -r finding; do
          [[ -z "$finding" ]] && continue
          # Only handle entries that look like file:line:content
          [[ "$finding" =~ ^[^:]+:[0-9]+: ]] || continue
          ((i++))
          # Cap per-check per-finding work to keep scan time bounded
          [[ $i -gt 5 ]] && break
          local analysis
          analysis=$(ai_analyze_finding "$check_id" "$check_name" "$finding" "high" "" 2>/dev/null)
          if [[ -n "$analysis" ]]; then
            echo "_AI assessment for \`$finding\`:_"
            echo ""
            ai_format_analysis "$analysis"
          fi
          if declare -f autofix_is_available >/dev/null 2>&1 && autofix_is_available; then
            local diff
            diff=$(autofix_generate "$check_id" "$check_name" "$finding" "high" 2>/dev/null)
            if [[ -n "$diff" ]]; then
              autofix_format "$diff"
            fi
          fi
        done <<< "$decoded"
      fi
    }

    # Status tables come first — clean executive view, no inline findings.
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

    # Addendum: code references for every FAIL/WARN row that has findings.
    # Kept at the end so the executive tables stay scannable. Findings are
    # ordered FAIL-first (highest priority), then WARN.
    has_any_findings=false
    for entry in "${fail_findings[@]}" "${warn_findings[@]}"; do
      IFS='|' read -r _check findings_enc <<< "$entry"
      [[ -n "$findings_enc" ]] && { has_any_findings=true; break; }
    done

    if $has_any_findings; then
      echo "---"
      echo ""
      echo "## Addendum — Code References"
      echo ""
      echo "Specific file:line:content for each FAIL/WARN finding. Use this section to navigate directly to the offending source. Findings are listed in priority order — FAILs first, then WARNs — and each entry corresponds to a row in the tables above."
      echo ""

      if [[ ${#fail_findings[@]} -gt 0 ]]; then
        echo "### FAIL findings"
        echo ""
        for entry in "${fail_findings[@]}"; do
          IFS='|' read -r check findings_enc <<< "$entry"
          [[ -n "$findings_enc" ]] && emit_findings_block "$check" "$findings_enc"
        done
      fi

      if [[ ${#warn_findings[@]} -gt 0 ]]; then
        echo "### WARN findings"
        echo ""
        for entry in "${warn_findings[@]}"; do
          IFS='|' read -r check findings_enc <<< "$entry"
          [[ -n "$findings_enc" ]] && emit_findings_block "$check" "$findings_enc"
        done
      fi
    fi

    echo "---"
    echo ""
    echo "${BRAND_FOOTER:-Preston-Check Enterprise Security Suite}"
    echo ""
    if [[ -n "${LICENSE_CUSTOMER:-}" && "${BRAND_NAME:-Preston-Check}" != "Preston-Check" ]]; then
      echo "Powered by Preston-Check · https://preston-check.com"
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
