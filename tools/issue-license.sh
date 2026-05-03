#!/bin/bash
###############################################################################
# tools/issue-license.sh — Issue a signed Preston-Check license
#
# Usage:
#   tools/issue-license.sh \
#     --customer acme-fintech \
#     --email ops@acme.example \
#     --tier pro \
#     --expires 2027-05-03 \
#     --max-repos 5 \
#     --output acme-fintech.license
#
# Requires:
#   - openssl (Ed25519 capable)
#   - The signing private key at ~/.preston-check/keys/private.pem
#     (run tools/setup-signing-key.sh first if you have not)
###############################################################################

set -euo pipefail

CUSTOMER=""
EMAIL=""
TIER=""
EXPIRES=""
MAX_REPOS=1
OUTPUT=""
LICENSE_ID=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --customer)   CUSTOMER="$2"; shift 2 ;;
    --email)      EMAIL="$2"; shift 2 ;;
    --tier)       TIER="$2"; shift 2 ;;
    --expires)    EXPIRES="$2"; shift 2 ;;
    --max-repos)  MAX_REPOS="$2"; shift 2 ;;
    --output)     OUTPUT="$2"; shift 2 ;;
    --license-id) LICENSE_ID="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^####/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$CUSTOMER" || -z "$TIER" || -z "$EXPIRES" ]]; then
  echo "ERROR: --customer, --tier, and --expires are required" >&2
  exit 1
fi

case "$TIER" in
  pro|enterprise) ;;
  *) echo "ERROR: --tier must be pro or enterprise" >&2; exit 1 ;;
esac

if [[ -z "$LICENSE_ID" ]]; then
  LICENSE_ID="PC-$(date +%Y)-$(openssl rand -hex 3 | tr 'a-f' 'A-F')"
fi
if [[ -z "$OUTPUT" ]]; then
  OUTPUT="${CUSTOMER}.license"
fi

PRIVATE_KEY="${PRESTON_PRIVATE_KEY:-${HOME}/.preston-check/keys/private.pem}"

if [[ ! -f "$PRIVATE_KEY" ]]; then
  echo "ERROR: signing key not found at $PRIVATE_KEY" >&2
  echo "Run tools/setup-signing-key.sh first." >&2
  exit 1
fi

# Normalize expires to ISO8601
if [[ "$EXPIRES" != *"T"* ]]; then
  EXPIRES="${EXPIRES}T00:00:00Z"
fi
ISSUED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PAYLOAD=$(printf '{"license_id":"%s","customer_id":"%s","customer_email":"%s","tier":"%s","issued_at":"%s","expires_at":"%s","max_repos":%d,"schema_version":1}' \
  "$LICENSE_ID" "$CUSTOMER" "$EMAIL" "$TIER" "$ISSUED_AT" "$EXPIRES" "$MAX_REPOS")

PAYLOAD_FILE=$(mktemp /tmp/preston-payload.XXXXXX)
SIG_FILE=$(mktemp /tmp/preston-sig.XXXXXX)
trap 'rm -f "$PAYLOAD_FILE" "$SIG_FILE"' EXIT

printf '%s' "$PAYLOAD" > "$PAYLOAD_FILE"

openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -rawin -in "$PAYLOAD_FILE" -out "$SIG_FILE"

PAYLOAD_B64=$(printf '%s' "$PAYLOAD" | base64 | tr -d '\n')
SIG_B64=$(base64 < "$SIG_FILE" | tr -d '\n')

# Wrap to 64 chars per line for PEM-style readability
wrap64() {
  fold -w 64
}

{
  echo "-----BEGIN PRESTON-CHECK LICENSE-----"
  echo "$PAYLOAD_B64" | wrap64
  echo "-----END PRESTON-CHECK LICENSE-----"
  echo "-----BEGIN PRESTON-CHECK SIGNATURE-----"
  echo "$SIG_B64" | wrap64
  echo "-----END PRESTON-CHECK SIGNATURE-----"
} > "$OUTPUT"

echo "License written to: $OUTPUT"
echo ""
echo "Customer instructions:"
echo "  mkdir -p ~/.preston-check"
echo "  cp $OUTPUT ~/.preston-check/license"
echo ""
echo "Or set PRESTON_LICENSE=/path/to/$OUTPUT"
