#!/bin/bash
###############################################################################
# lib/check_metadata.sh — Check metadata schema parser
#
# Parses YAML metadata embedded between PRESTON_META heredoc markers in check
# scripts and exposes META_* environment variables for the runner. Falls back
# to filename-derived metadata for legacy checks without a metadata block,
# preserving backward compatibility with the original 112 checks.
#
# Usage:
#   source lib/check_metadata.sh
#   parse_check_metadata /path/to/checks/community/proposed/201-my-check.sh
#   echo "$META_ID $META_NAME $META_MIN_TIER $META_TRUST_TIER"
#
# Trust tier policy: derived from filesystem path, NEVER from declared metadata.
# This prevents contributors from claiming a higher trust tier than earned.
###############################################################################

CHECK_META_REQUIRED_FIELDS=(
  schema_version id name description category severity languages
  min_tier runtime_class evidence_required version added_in author_name
)

reset_check_metadata() {
  # Reset to empty string (not unset) so indirect lookup works under set -u
  META_SCHEMA_VERSION=""; META_ID=""; META_NAME=""; META_DESCRIPTION=""
  META_CATEGORY=""; META_SEVERITY=""; META_LANGUAGES=""; META_MIN_TIER=""
  META_TRUST_TIER=""; META_RUNTIME_CLASS=""; META_EVIDENCE_REQUIRED=""
  META_VERSION=""; META_ADDED_IN=""; META_DEPRECATED_IN=""; META_REPLACED_BY=""
  META_AUTHOR_NAME=""; META_AUTHOR_GITHUB=""; META_AUTHOR_ORG=""
  META_FRAMEWORKS=""; META_CWE=""; META_OWASP=""; META_NIST_CSF=""
  META_FALSE_POSITIVE_RATE=""; META_PERFORMANCE_CLASS=""; META_ORIGIN=""
}

# Portable uppercase (works on bash 3.2, no ${var^^} required)
_meta_upper() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

extract_yaml_block() {
  local file="$1"
  # The heredoc opener line contains << and PRESTON_META together.
  # The heredoc closer line is just PRESTON_META on its own.
  local start end
  start=$(grep -n "<<.*PRESTON_META" "$file" 2>/dev/null | head -1 | cut -d: -f1)
  end=$(grep -n "^PRESTON_META[[:space:]]*$" "$file" 2>/dev/null | head -1 | cut -d: -f1)
  if [[ -n "$start" && -n "$end" && $end -gt $start ]]; then
    sed -n "$((start+1)),$((end-1))p" "$file"
  fi
}

parse_meta_field() {
  local line="$1"
  local key value
  key="${line%%:*}"
  key="${key#"${key%%[![:space:]]*}"}"
  value="${line#*:}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ "${value:0:1}" == "\"" && "${value: -1}" == "\"" ]]; then
    value="${value:1:-1}"
  fi
  printf '%s\n' "$key=$value"
}

trust_tier_from_path() {
  local path="$1"
  case "$path" in
    */checks/community/proposed/*) echo "proposed" ;;
    */checks/community/accepted/*) echo "accepted" ;;
    */checks/community/verified/*) echo "verified" ;;
    */checks/core/*) echo "core" ;;
    */checks/*) echo "core" ;;
    *) echo "unknown" ;;
  esac
}

infer_legacy_metadata() {
  local file="$1"
  local basename num
  basename="$(basename "$file" .sh)"
  num="$(echo "$basename" | grep -oE '^[0-9]+' || echo "0")"

  META_ID="P-$(printf '%02d' "$num" 2>/dev/null || echo "$num")"
  META_NAME="${basename#*-}"
  META_NAME="${META_NAME//-/ }"
  META_CATEGORY="code-scan"
  META_SEVERITY="medium"
  META_LANGUAGES="any"
  META_MIN_TIER="free"
  META_RUNTIME_CLASS="static-grep"
  META_EVIDENCE_REQUIRED="false"
  META_VERSION="0.1.0"
  META_ADDED_IN="0.1.0"
  META_AUTHOR_NAME="Preston-Check Maintainers"
  META_AUTHOR_GITHUB=""
  META_TRUST_TIER="$(trust_tier_from_path "$file")"
}

parse_check_metadata() {
  local file="$1"
  reset_check_metadata

  local yaml
  yaml="$(extract_yaml_block "$file")"

  if [[ -z "$yaml" ]]; then
    infer_legacy_metadata "$file"
    return 0
  fi

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    case "$line" in
      *:*)
        local kv key value
        kv="$(parse_meta_field "$line")"
        key="${kv%%=*}"
        value="${kv#*=}"
        case "$key" in
          schema_version) META_SCHEMA_VERSION="$value" ;;
          id) META_ID="$value" ;;
          name) META_NAME="$value" ;;
          description) META_DESCRIPTION="$value" ;;
          category) META_CATEGORY="$value" ;;
          severity) META_SEVERITY="$value" ;;
          languages) META_LANGUAGES="$value" ;;
          min_tier) META_MIN_TIER="$value" ;;
          runtime_class) META_RUNTIME_CLASS="$value" ;;
          evidence_required) META_EVIDENCE_REQUIRED="$value" ;;
          version) META_VERSION="$value" ;;
          added_in) META_ADDED_IN="$value" ;;
          deprecated_in) META_DEPRECATED_IN="$value" ;;
          replaced_by) META_REPLACED_BY="$value" ;;
          author_name) META_AUTHOR_NAME="$value" ;;
          author_github) META_AUTHOR_GITHUB="$value" ;;
          author_org) META_AUTHOR_ORG="$value" ;;
          frameworks) META_FRAMEWORKS="$value" ;;
          cwe) META_CWE="$value" ;;
          owasp) META_OWASP="$value" ;;
          nist_csf) META_NIST_CSF="$value" ;;
          false_positive_rate) META_FALSE_POSITIVE_RATE="$value" ;;
          performance_class) META_PERFORMANCE_CLASS="$value" ;;
          origin) META_ORIGIN="$value" ;;
        esac
        ;;
    esac
  done <<< "$yaml"

  META_TRUST_TIER="$(trust_tier_from_path "$file")"

  : "${META_LANGUAGES:=any}"
  : "${META_MIN_TIER:=free}"
  : "${META_RUNTIME_CLASS:=static-grep}"
  : "${META_EVIDENCE_REQUIRED:=false}"
  : "${META_SEVERITY:=medium}"

  return 0
}

validate_check_metadata() {
  local file="$1"
  local missing=()
  local field var
  for field in "${CHECK_META_REQUIRED_FIELDS[@]}"; do
    var="META_$(_meta_upper "$field")"
    if [[ -z "${!var:-}" ]]; then
      missing+=("$field")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: $file is missing required metadata fields: ${missing[*]}" >&2
    return 1
  fi
  return 0
}

# Open-core: every check runs for every user. The min_tier metadata field
# remains for documentation, framework-scoped reporting, and informational
# grouping in the audit-package SaaS, but it does NOT gate local execution.
# Returning success unconditionally is intentional and aligns with the
# Snyk / Semgrep / Trivy open-core playbook: scanner free, SaaS paid.
tier_allows_check() {
  return 0
}

export -f parse_check_metadata validate_check_metadata tier_allows_check
export -f trust_tier_from_path reset_check_metadata extract_yaml_block
