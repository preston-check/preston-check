#!/bin/bash
###############################################################################
# tools/lint-check.sh — Community check linter
#
# Validates that a community-contributed check meets the safety bar required
# for inclusion. Run before submitting a PR; CI runs the same gates.
#
# Usage:
#   tools/lint-check.sh checks/community/proposed/217-my-check.sh
###############################################################################

set -uo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <check_file>"
  exit 1
fi

FILE="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$FILE" ]]; then
  echo "ERROR: file not found: $FILE"
  exit 1
fi

ERRORS=0
WARNINGS=0

err()  { echo "ERROR: $*" >&2; ((ERRORS++)); }
warn() { echo "WARN:  $*" >&2; ((WARNINGS++)); }
ok()   { echo "OK:    $*"; }

# 1. shellcheck if available
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S warning "$FILE" >/dev/null 2>&1; then
    ok "shellcheck"
  else
    warn "shellcheck reported issues; run 'shellcheck $FILE' to see them"
  fi
else
  warn "shellcheck not installed; skipping (CI will run it)"
fi

# 2. Forbidden constructs — network calls, eval, exec, arbitrary file writes
#
# Delegated to tools/sandbox_validate.py rather than matched with regexes. The
# pattern list this replaced scanned the PRESTON_META block instead of the code:
# its awk boundary toggled only on the closing delimiter, never on the opening
# `: <<'PRESTON_META'`, so it inspected the metadata prose and skipped the script
# body entirely. That inverted both directions — it flagged descriptions
# containing "ussync parameters" while passing a check whose body called curl and
# eval (2026-08-31; see docs/pipeline-reliability.md). sandbox_validate parses the
# script with bashlex and fails closed, and is the same gate the threat-intel
# pipeline already runs on every synthesized candidate.
SANDBOX="$SCRIPT_DIR/tools/sandbox_validate.py"
if ! command -v python3 >/dev/null 2>&1; then
  err "python3 not found; cannot verify forbidden constructs (this gate fails closed)"
elif [[ ! -f "$SANDBOX" ]]; then
  err "sandbox_validate.py not found at $SANDBOX; cannot verify forbidden constructs"
elif SANDBOX_OUT=$(python3 "$SANDBOX" "$FILE" 2>&1); then
  ok "no forbidden constructs"
else
  err "forbidden construct detected (network calls, eval, and exec are banned in community checks)"
  printf '%s\n' "$SANDBOX_OUT" | sed 's/^/       /' >&2
fi

# 3. PRESTON_META block exists
if ! grep -q "^[[:space:]]*PRESTON_META[[:space:]]*$" "$FILE"; then
  err "missing PRESTON_META metadata block"
else
  ok "PRESTON_META block present"
fi

# 4. Required metadata fields
source "$SCRIPT_DIR/lib/check_metadata.sh"
parse_check_metadata "$FILE"

REQUIRED=(
  schema_version id name description category severity languages
  min_tier runtime_class evidence_required version added_in author_name
)
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }
for field in "${REQUIRED[@]}"; do
  var="META_$(upper "$field")"
  if [[ -z "${!var:-}" ]]; then
    err "missing required metadata field: $field"
  fi
done
[[ ${#REQUIRED[@]} -gt 0 ]] && [[ $ERRORS -eq 0 ]] && ok "all required metadata fields present"

# 5. ID range check (community: 200-999, core: 1-199)
case "$FILE" in
  */checks/community/*)
    num=$(echo "${META_ID:-}" | grep -oE '[0-9]+$' || echo "0")
    if [[ ${num:-0} -lt 200 || ${num:-0} -gt 999 ]]; then
      err "community check ID must be in range P-200..P-999 (got ${META_ID})"
    fi
    ;;
esac

# 6. Runtime class restriction for community
case "$FILE" in
  */checks/community/*)
    if [[ "${META_RUNTIME_CLASS:-}" != "static-grep" ]]; then
      err "community checks must declare runtime_class: static-grep (got ${META_RUNTIME_CLASS})"
    fi
    ;;
esac

# 7. Severity in controlled vocabulary
case "${META_SEVERITY:-}" in
  critical|high|medium|low|info) ok "severity is valid" ;;
  *) err "severity must be one of: critical, high, medium, low, info (got ${META_SEVERITY})" ;;
esac

# 8. min_tier in controlled vocabulary
case "${META_MIN_TIER:-}" in
  free|pro|enterprise) ok "min_tier is valid" ;;
  *) err "min_tier must be one of: free, pro, enterprise (got ${META_MIN_TIER})" ;;
esac

echo ""
echo "============================================================================"
if [[ $ERRORS -gt 0 ]]; then
  echo "  FAIL: $ERRORS errors, $WARNINGS warnings"
  exit 1
fi
echo "  PASS: 0 errors, $WARNINGS warnings"
echo "============================================================================"
