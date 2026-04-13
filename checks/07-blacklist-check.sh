#!/bin/bash
# P-07: Blacklist enforcement
# Preston created multiple accounts after being blacklisted.
# All account creation, name changes, and KYC flows must check the blacklist.

echo "P-07: Blacklist Enforcement"

SRC="${SOURCE_DIR:-.}"

# Check for blacklist check in registration
reg_check=$(grep -rn --include="*.java" \
  "BlacklistCheck\|blacklist.*check\|checkBlacklist\|isBlacklisted" \
  "$SRC" 2>/dev/null \
  | grep -i "regist\|signup\|create.*user\|create.*client\|name.*change\|vouched" \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$reg_check" ]]; then
  record "PASS" "P-07 Blacklist in registration" "Blacklist check found in registration/KYC flow"
else
  record "FAIL" "P-07 Blacklist in registration" "No blacklist check in registration or KYC paths"
fi

# Check for blacklist check on name changes
name_check=$(grep -rn --include="*.java" \
  "BlacklistCheck\|blacklist" \
  "$SRC" 2>/dev/null \
  | grep -i "name.*change\|applyName\|confirmName\|pending.*name" \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$name_check" ]]; then
  record "PASS" "P-07 Blacklist on name change" "Name changes check against blacklist"
else
  record "FAIL" "P-07 Blacklist on name change" "Name changes do NOT check blacklist — re-entry vector"
fi
