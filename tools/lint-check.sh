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

# 2. Forbidden patterns
FORBIDDEN_PATTERNS=(
  "curl[[:space:]]"
  "wget[[:space:]]"
  "nc[[:space:]]"
  "ncat[[:space:]]"
  "telnet[[:space:]]"
  "ssh[[:space:]]"
  "scp[[:space:]]"
  "rsync[[:space:]]"
  "ftp[[:space:]]"
  "/dev/tcp"
  "/dev/udp"
  "[[:space:]]eval[[:space:]]"
  "[[:space:]]source[[:space:]]\\\$"
  "exec[[:space:]]+[\$\"']"
)

for pat in "${FORBIDDEN_PATTERNS[@]}"; do
  # Skip lines inside the PRESTON_META block (where these words may appear in metadata strings)
  if awk '/^[[:space:]]*PRESTON_META[[:space:]]*$/{flag=!flag; next} !flag' "$FILE" | \
     grep -nE "$pat" >/dev/null 2>&1; then
    err "Forbidden pattern detected: '$pat' (network calls, eval, and exec are banned in community checks)"
  fi
done
[[ $ERRORS -eq 0 ]] && ok "no forbidden patterns"

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
