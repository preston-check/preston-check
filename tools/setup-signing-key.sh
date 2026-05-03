#!/bin/bash
###############################################################################
# tools/setup-signing-key.sh — One-time Ed25519 keypair generator
#
# Run this ONCE on the machine where you will issue licenses. The private
# key stays on your laptop (in ~/.preston-check/keys/private.pem). The
# public key is written into lib/license_pubkey.pem and committed to the
# repository so customer instances can verify licenses offline.
#
# IMPORTANT: Back up the private key. Losing it means all existing
# licenses become unverifiable, because regenerating the keypair invalidates
# every license you have issued.
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS_DIR="${HOME}/.preston-check/keys"
PRIVATE_KEY="${KEYS_DIR}/private.pem"
PUBLIC_KEY="${KEYS_DIR}/public.pem"
REPO_PUBKEY="${SCRIPT_DIR}/lib/license_pubkey.pem"

mkdir -p "$KEYS_DIR"
chmod 700 "$KEYS_DIR"

if [[ -f "$PRIVATE_KEY" ]]; then
  echo "WARNING: A signing keypair already exists at $PRIVATE_KEY"
  echo ""
  echo "Regenerating will invalidate every existing license. If you really"
  echo "want to rotate the key, delete the existing files manually and re-run."
  echo ""
  echo "  rm $PRIVATE_KEY $PUBLIC_KEY"
  echo ""
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required and was not found on PATH."
  exit 1
fi

echo "Generating Ed25519 signing keypair..."
openssl genpkey -algorithm Ed25519 -out "$PRIVATE_KEY" 2>/dev/null
chmod 600 "$PRIVATE_KEY"
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null
chmod 644 "$PUBLIC_KEY"

cp "$PUBLIC_KEY" "$REPO_PUBKEY"

echo ""
echo "Keys generated:"
echo "  Private (KEEP SECRET):  $PRIVATE_KEY"
echo "  Public  (in repo):      $REPO_PUBKEY"
echo ""
echo "Public key fingerprint:"
openssl pkey -in "$PUBLIC_KEY" -pubin -outform DER 2>/dev/null | \
  openssl dgst -sha256 -hex | awk '{print "  "$2}'
echo ""
echo "Next steps:"
echo "  1. BACK UP $PRIVATE_KEY to a secure offline location."
echo "  2. Commit lib/license_pubkey.pem to git."
echo "  3. Issue licenses with: tools/issue-license.sh"
