#!/bin/bash
# P-07: Blacklist enforcement
# Preston created multiple accounts after being blacklisted.
# All account creation, name changes, and KYC flows must check the blacklist.

echo "P-07: Blacklist Enforcement"

SRC="${SOURCE_DIR:-.}"

# Check for blacklist check in registration/auth
reg_check=$(grep -rn --include="$SRC_EXT" \
  "$BLACKLIST_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -iv "test\|Test\|target\|vendor\|_test\.go" \
  | grep -i "regist\|signup\|create.*user\|create.*client\|auth\|login\|CheckAndBlock" \
  | head -5)

if [[ -n "$reg_check" ]]; then
  record "PASS" "P-07 Blacklist in registration" "Blacklist check found in registration/auth flow"
else
  record "FAIL" "P-07 Blacklist in registration" "No blacklist check in registration or KYC paths"
fi

# Check for blacklist check on name changes / profile updates
name_check=$(grep -rn --include="$SRC_EXT" \
  "$BLACKLIST_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -iv "test\|Test\|target\|vendor\|_test\.go" \
  | grep -i "name.*change\|applyName\|confirmName\|pending.*name\|UpdateProfile\|profile.*update" \
  | head -5)

if [[ -n "$name_check" ]]; then
  record "PASS" "P-07 Blacklist on name change" "Name changes check against blacklist"
else
  record "FAIL" "P-07 Blacklist on name change" "Name changes do NOT check blacklist — re-entry vector"
fi
