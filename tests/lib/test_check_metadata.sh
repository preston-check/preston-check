###############################################################################
# tests/lib/test_check_metadata.sh
# Sourced by tests/run-tests.sh; uses PASS/FAIL counters from the runner.
###############################################################################

source "$ROOT/lib/check_metadata.sh"

echo "  --- check_metadata parser ---"

# Test 1: parse a real check with metadata
parse_check_metadata "$ROOT/checks/01-hardcoded-secrets.sh"
assert "P-01 id parsed"           "$META_ID" "P-01"
assert "P-01 schema_version"      "$META_SCHEMA_VERSION" "1"
assert "P-01 severity"            "$META_SEVERITY" "critical"
assert "P-01 min_tier"            "$META_MIN_TIER" "free"
assert "P-01 trust_tier from path" "$META_TRUST_TIER" "core"
assert_contains "P-01 frameworks include PCI-DSS" "$META_FRAMEWORKS" "PCI-DSS:4.0"
assert_contains "P-01 frameworks include NIST-CSF" "$META_FRAMEWORKS" "NIST-CSF:2.0"
assert_contains "P-01 OWASP-API not double-yeared" "$META_FRAMEWORKS" "OWASP-API:2023:API8"
if [[ "$META_FRAMEWORKS" == *":2023:API8:2023"* ]]; then
  FAIL=$((FAIL+1)); FAIL_NAMES+=("P-01 OWASP-API duplicated year")
  echo "  FAIL: P-01 OWASP-API has duplicated year"
else
  PASS=$((PASS+1))
  echo "  PASS: P-01 OWASP-API has no duplicated year"
fi

echo "  --- trust tier derivation ---"
assert "core path"      "$(trust_tier_from_path /repo/checks/01-foo.sh)"                      "core"
assert "core dir"       "$(trust_tier_from_path /repo/checks/core/100-bar.sh)"                 "core"
assert "verified"       "$(trust_tier_from_path /repo/checks/community/verified/210-baz.sh)"    "verified"
assert "accepted"       "$(trust_tier_from_path /repo/checks/community/accepted/220-qux.sh)"    "accepted"
assert "proposed"       "$(trust_tier_from_path /repo/checks/community/proposed/230-quux.sh)"   "proposed"

echo "  --- tier_allows_check policy ---"
_check_tier() {
  local desc="$1" check_t="$2" lic_t="$3" want="$4"
  if tier_allows_check "$check_t" "$lic_t"; then result="allow"; else result="deny"; fi
  if [[ "$result" == "$want" ]]; then
    PASS=$((PASS+1))
    echo "  PASS: $desc"
  else
    FAIL=$((FAIL+1)); FAIL_NAMES+=("$desc")
    echo "  FAIL: $desc (expected $want, got $result)"
  fi
}
_check_tier "free check, free user → allow"          free       free       allow
_check_tier "pro check, free user → deny"            pro        free       deny
_check_tier "pro check, pro user → allow"            pro        pro        allow
_check_tier "enterprise check, free user → deny"     enterprise free       deny
_check_tier "enterprise check, enterprise → allow"   enterprise enterprise allow

echo "  --- crypto suite metadata ---"
parse_check_metadata "$ROOT/checks/301-smart-contract-reentrancy.sh"
assert "P-301 id"           "$META_ID" "P-301"
assert "P-301 severity"     "$META_SEVERITY" "critical"
assert_contains "P-301 frameworks OWASP-SC" "$META_FRAMEWORKS" "OWASP-SC-Top-10:2025"
