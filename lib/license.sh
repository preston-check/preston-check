#!/bin/bash
###############################################################################
# lib/license.sh — Preston-Check license verification and tier enforcement
#
# License model:
#   - Free tier: no license file required; all scanning checks (P-01..P-103+)
#     run without any signup, email, or telemetry.
#   - Pro / Enterprise: signed license file from Preston-Check.
#   - STRICT enforcement: expired Pro/Enterprise licenses block tool execution
#     for paid features. Free tier always remains accessible.
#   - 30-day pre-expiry warning window: every report prints a renewal banner
#     during the final 30 days of license validity.
#
# License envelope format (PEM-style):
#   -----BEGIN PRESTON-CHECK LICENSE-----
#   <base64 of UTF-8 JSON payload>
#   -----END PRESTON-CHECK LICENSE-----
#   -----BEGIN PRESTON-CHECK SIGNATURE-----
#   <base64 of Ed25519 signature over the decoded JSON bytes>
#   -----END PRESTON-CHECK SIGNATURE-----
#
# Payload schema:
#   {
#     "license_id":     "PC-2026-A1B2C3",
#     "customer_id":    "acme-fintech",
#     "customer_email": "ops@acme.example",
#     "tier":           "pro",                    // pro | enterprise
#     "issued_at":      "2026-05-03T00:00:00Z",
#     "expires_at":     "2027-05-03T00:00:00Z",
#     "max_repos":      5,
#     "schema_version": 1
#   }
###############################################################################

LICENSE_TIER="free"
LICENSE_VALID="false"
LICENSE_CUSTOMER=""
LICENSE_EXPIRES_AT=""
LICENSE_EXPIRES_EPOCH=0
LICENSE_DAYS_REMAINING=-1
LICENSE_WARNING=""
LICENSE_ERROR=""
LICENSE_REPOS=""

LICENSE_PUBKEY="${PRESTON_PUBKEY:-${SCRIPT_DIR:-.}/lib/license_pubkey.pem}"
LICENSE_FILE="${PRESTON_LICENSE:-${HOME}/.preston-check/license}"

date_to_epoch() {
  local d="$1"
  if date --version 2>/dev/null | grep -q GNU; then
    date -d "$d" +%s 2>/dev/null
  else
    date -j -f "%Y-%m-%dT%H:%M:%SZ" "$d" +%s 2>/dev/null || \
    date -j -f "%Y-%m-%d" "$d" +%s 2>/dev/null
  fi
}

b64_decode() {
  if base64 --help 2>&1 | grep -q -- '-D'; then
    base64 -D 2>/dev/null
  else
    base64 -d 2>/dev/null
  fi
}

extract_pem_block() {
  local marker="$1" file="$2"
  awk -v begin="-----BEGIN $marker-----" -v end="-----END $marker-----" '
    $0 == begin { flag=1; next }
    $0 == end   { flag=0 }
    flag        { print }
  ' "$file" | tr -d ' \n'
}

json_string_field() {
  local field="$1" json="$2"
  echo "$json" | grep -oE "\"$field\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | \
    sed -E "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"/\1/"
}

verify_signature() {
  local payload="$1" sig_file="$2" pubkey="$3"
  local payload_file
  payload_file=$(mktemp /tmp/preston-payload.XXXXXX)
  printf '%s' "$payload" > "$payload_file"
  if openssl pkeyutl -verify -pubin -inkey "$pubkey" -rawin -in "$payload_file" -sigfile "$sig_file" >/dev/null 2>&1; then
    rm -f "$payload_file"
    return 0
  fi
  rm -f "$payload_file"
  return 1
}

load_license() {
  if [[ ! -f "$LICENSE_FILE" ]]; then
    LICENSE_TIER="free"
    LICENSE_VALID="false"
    return 0
  fi

  if [[ ! -f "$LICENSE_PUBKEY" ]]; then
    LICENSE_TIER="free"
    LICENSE_ERROR="public key not found at $LICENSE_PUBKEY"
    return 0
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    LICENSE_TIER="free"
    LICENSE_ERROR="openssl not installed; cannot verify license"
    return 0
  fi

  local payload_b64 sig_b64
  payload_b64=$(extract_pem_block "PRESTON-CHECK LICENSE" "$LICENSE_FILE")
  sig_b64=$(extract_pem_block "PRESTON-CHECK SIGNATURE" "$LICENSE_FILE")

  if [[ -z "$payload_b64" || -z "$sig_b64" ]]; then
    LICENSE_TIER="free"
    LICENSE_ERROR="malformed license file"
    return 0
  fi

  local payload
  payload=$(printf '%s' "$payload_b64" | b64_decode)
  if [[ -z "$payload" ]]; then
    LICENSE_TIER="free"
    LICENSE_ERROR="failed to decode license payload"
    return 0
  fi

  local sig_file
  sig_file=$(mktemp /tmp/preston-sig.XXXXXX)
  printf '%s' "$sig_b64" | b64_decode > "$sig_file"

  if ! verify_signature "$payload" "$sig_file" "$LICENSE_PUBKEY"; then
    rm -f "$sig_file"
    LICENSE_TIER="free"
    LICENSE_ERROR="invalid license signature"
    return 0
  fi
  rm -f "$sig_file"

  local tier customer expires_at
  tier=$(json_string_field "tier" "$payload")
  customer=$(json_string_field "customer_id" "$payload")
  expires_at=$(json_string_field "expires_at" "$payload")

  if [[ -z "$tier" || -z "$expires_at" ]]; then
    LICENSE_TIER="free"
    LICENSE_ERROR="license missing required fields"
    return 0
  fi

  local now expires_epoch
  now=$(date +%s)
  expires_epoch=$(date_to_epoch "$expires_at")

  if [[ -z "$expires_epoch" ]]; then
    LICENSE_TIER="free"
    LICENSE_ERROR="invalid expiry date in license: $expires_at"
    return 0
  fi

  LICENSE_EXPIRES_AT="$expires_at"
  LICENSE_EXPIRES_EPOCH="$expires_epoch"
  LICENSE_DAYS_REMAINING=$(( (expires_epoch - now) / 86400 ))

  if [[ $now -ge $expires_epoch ]]; then
    LICENSE_TIER="free"
    LICENSE_VALID="false"
    LICENSE_ERROR="license expired on $expires_at"
    LICENSE_CUSTOMER="$customer"
    return 0
  fi

  if [[ $LICENSE_DAYS_REMAINING -le 30 ]]; then
    LICENSE_WARNING="License expires in $LICENSE_DAYS_REMAINING days ($expires_at). Renew at preston-check.dev/renew/$customer to avoid CI disruption."
  fi

  LICENSE_TIER="$tier"
  LICENSE_VALID="true"
  LICENSE_CUSTOMER="$customer"
  return 0
}

# Strict enforcement: hard exit if user tries to use paid features without a valid license.
enforce_license_strict() {
  local requested_tier="$1"
  if [[ "$requested_tier" == "free" ]]; then
    return 0
  fi
  if [[ "$LICENSE_VALID" != "true" ]]; then
    echo ""
    echo "============================================================================"
    echo "  PRESTON-CHECK — LICENSE REQUIRED"
    echo "============================================================================"
    echo ""
    if [[ -n "$LICENSE_ERROR" ]]; then
      echo "  Error: $LICENSE_ERROR"
    else
      echo "  No valid license found at $LICENSE_FILE"
    fi
    echo ""
    echo "  $requested_tier features require a valid license."
    echo "  Free tier (P-01 to P-103+ scanning) is always available without a license."
    echo ""
    echo "  Get a license:    https://preston-check.dev/buy"
    echo "  Renew existing:   https://preston-check.dev/renew"
    echo "  Install license:  $LICENSE_FILE"
    echo ""
    exit 2
  fi

  case "$LICENSE_TIER" in
    free)
      if [[ "$requested_tier" != "free" ]]; then
        echo "ERROR: $requested_tier features require a Pro or Enterprise license." >&2
        exit 2
      fi
      ;;
    pro)
      if [[ "$requested_tier" == "enterprise" ]]; then
        echo "ERROR: Enterprise features require an Enterprise license. Current: Pro." >&2
        exit 2
      fi
      ;;
    enterprise) ;;
  esac
}

print_license_status() {
  if [[ "$LICENSE_VALID" == "true" ]]; then
    echo "  License: $LICENSE_TIER (customer: $LICENSE_CUSTOMER, expires: $LICENSE_EXPIRES_AT, $LICENSE_DAYS_REMAINING days)"
    if [[ -n "$LICENSE_WARNING" ]]; then
      echo "  WARNING: $LICENSE_WARNING"
    fi
  else
    echo "  License: free tier (no license installed)"
    if [[ -n "$LICENSE_ERROR" ]]; then
      echo "  Note: $LICENSE_ERROR"
    fi
  fi
}

export -f load_license enforce_license_strict print_license_status
