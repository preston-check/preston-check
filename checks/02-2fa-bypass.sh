#!/bin/bash
# P-02: 2FA bypass paths
# Preston created accounts with 2FA=NONE. This check verifies that no code path
# allows 2FA to be set to NONE without explicit admin override.

echo "P-02: 2FA Bypass Paths"

SRC="${SOURCE_DIR:-.}"

# Check for auth_skip or 2FA NONE hardcoding
bypass=$(grep -rn --include="*.java" \
  "auth_skip\|required_2fa_2proceed.*NONE\|2fa.*NONE\|skip.*2fa\|bypass.*2fa" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|mock\|Mock\|target\|node_modules\|// \|/\*\|WARN\|log\.\|memory" \
  | head -10)

if [[ -z "$bypass" ]]; then
  record "PASS" "P-02 2FA bypass paths" "No 2FA bypass patterns found"
else
  count=$(echo "$bypass" | wc -l)
  record "WARN" "P-02 2FA bypass paths" "$count potential 2FA bypass paths (review manually)"
  if $VERBOSE; then echo "$bypass"; fi
fi

# Check if new accounts can be created with 2FA=NONE
none_default=$(grep -rn --include="*.java" \
  "default_2fa_state.*auth_skip\|NONE.*2fa_state\|set2faState.*NONE" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -z "$none_default" ]]; then
  record "PASS" "P-02 2FA default state" "No default-to-NONE 2FA patterns"
else
  record "FAIL" "P-02 2FA default state" "Found code that defaults 2FA to NONE/skip"
fi
