###############################################################################
# tests/lib/test_license.sh
# Sourced by tests/run-tests.sh.
###############################################################################

SCRIPT_DIR="$ROOT"
source "$ROOT/lib/license.sh"

echo "  --- license loader ---"

# Test 1: missing license file → free tier
LICENSE_FILE=/tmp/preston-test-nolicense-$$
load_license
assert "no license file → free tier"   "$LICENSE_TIER" "free"
assert "no license → invalid"           "$LICENSE_VALID" "false"

# Test 2: malformed license file → free tier
LICENSE_FILE=$(mktemp /tmp/preston-test-malformed.XXXXXX)
echo "garbage content" > "$LICENSE_FILE"
load_license
assert "malformed → free tier"          "$LICENSE_TIER" "free"
assert_contains "malformed → error"     "$LICENSE_ERROR" "malformed"
rm -f "$LICENSE_FILE"

# Test 3: PEM block extraction
LICENSE_FILE=$(mktemp /tmp/preston-test-extract.XXXXXX)
cat > "$LICENSE_FILE" <<'EOF'
-----BEGIN PRESTON-CHECK LICENSE-----
SGVsbG8sIFdvcmxkIQ==
-----END PRESTON-CHECK LICENSE-----
-----BEGIN PRESTON-CHECK SIGNATURE-----
c2lnbmF0dXJlYmxvYg==
-----END PRESTON-CHECK SIGNATURE-----
EOF

extracted=$(extract_pem_block "PRESTON-CHECK LICENSE" "$LICENSE_FILE")
assert "extract LICENSE block"  "$extracted" "SGVsbG8sIFdvcmxkIQ=="
extracted=$(extract_pem_block "PRESTON-CHECK SIGNATURE" "$LICENSE_FILE")
assert "extract SIGNATURE block" "$extracted" "c2lnbmF0dXJlYmxvYg=="
rm -f "$LICENSE_FILE"
