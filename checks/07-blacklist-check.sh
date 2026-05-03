#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-07
name: Blacklist Check
description: Verifies registration/KYC paths check the blacklist.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:8.2.4, SOC2:TSC-2017:CC6.2, ISO-27001:2022:5.16, OWASP-API:2023:API2, NIST-CSF:2.0:PR.AA-1, CIS-v8:5.3
PRESTON_META


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
  record "FAIL" "P-07 Blacklist in registration" "No blacklist check in registration or KYC paths" "$(echo "$reg_check" | head -10)"
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
  record "FAIL" "P-07 Blacklist on name change" "Name changes do NOT check blacklist — re-entry vector" "$(echo "$name_check" | head -10)"
fi
