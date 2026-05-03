#!/bin/bash
###############################################################################
# lib/telemetry.sh — Opt-in anonymous score telemetry
#
# Telemetry is OFF BY DEFAULT. The user must explicitly opt in via:
#   - --telemetry-opt-in flag
#   - PRESTON_TELEMETRY=1 env var
#   - "telemetry: opt_in" in config
#
# WHAT IS SENT (only when opt-in):
#   - Tool version, license tier, primary language
#   - Aggregate counts: pass / fail / warn / skip / total
#   - SHA-256 hash of the git remote origin URL (or source path if no git)
#   - UTC timestamp
#
# WHAT IS NEVER SENT:
#   - Any source code content
#   - File paths, file names, customer details
#   - Specific check names that failed
#
# Telemetry is the ONLY network call this tool ever makes, and it is disabled
# entirely under --airgap. The function is intentionally short and easy to
# audit because the privacy claim depends on you reading it.
###############################################################################

TELEMETRY_OPT_IN="false"
TELEMETRY_ENDPOINT="${PRESTON_TELEMETRY_ENDPOINT:-https://preston-check.dev/api/v1/telemetry}"

is_telemetry_enabled() {
  [[ "$TELEMETRY_OPT_IN" == "true" ]] && return 0
  return 1
}

compute_repo_hash() {
  local src="${SOURCE_DIR:-.}"
  local origin=""
  if [[ -d "$src/.git" ]] && command -v git >/dev/null 2>&1; then
    origin=$(git -C "$src" config --get remote.origin.url 2>/dev/null || true)
  fi
  if [[ -z "$origin" ]]; then
    origin="$src"
  fi
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$origin" | shasum -a 256 | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$origin" | sha256sum | cut -d' ' -f1
  else
    echo "unhashable"
  fi
}

# Send opt-in telemetry. Fails silently and never blocks the scan.
send_telemetry() {
  if ! is_telemetry_enabled; then
    return 0
  fi
  if [[ "${AIRGAP_MODE:-false}" == "true" ]]; then
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi

  local pass="$1" fail="$2" warn="$3" skip="$4" total="$5" lang="${6:-unknown}"
  local repo_hash
  repo_hash=$(compute_repo_hash)
  local ts
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  local payload
  payload=$(printf '{"version":"%s","tier":"%s","lang":"%s","repo_hash":"%s","pass":%d,"fail":%d,"warn":%d,"skip":%d,"total":%d,"timestamp":"%s"}' \
    "${PRESTON_VERSION:-1.0.0}" "${LICENSE_TIER:-free}" "$lang" "$repo_hash" \
    "$pass" "$fail" "$warn" "$skip" "$total" "$ts")

  curl -s -m 5 -X POST -H "Content-Type: application/json" \
    -d "$payload" "$TELEMETRY_ENDPOINT" >/dev/null 2>&1 &
  return 0
}

print_telemetry_status() {
  if is_telemetry_enabled; then
    echo "  Telemetry: opt-in (anonymous score reported to $TELEMETRY_ENDPOINT)"
  else
    echo "  Telemetry: off (use --telemetry-opt-in to contribute to State of Fintech Security)"
  fi
}

export -f is_telemetry_enabled send_telemetry print_telemetry_status compute_repo_hash
