#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-53
name: Account Lifecycle
description: Checks account locking, email change verification.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:8.1.4, PCI-DSS:4.0:8.2.4, SOC2:TSC-2017:CC6.2, SOC2:TSC-2017:CC6.3, ISO-27001:2022:5.16, ISO-27001:2022:5.18, NIST-CSF:2.0:PR.AA-1, CIS-v8:5.3
PRESTON_META


# P-53: Account Lifecycle Security
# Account creation, suspension, closure must be audited and irreversible where needed.
echo "P-53: Account Lifecycle"
SRC="${SOURCE_DIR:-.}"
account_lock=$(grep -rn --include="*.java" \
  "account_locked\|lockAccount\|suspendAccount\|freezeAccount\|deactivateAccount\|login_attempts" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$account_lock" ]]; then
  record "PASS" "P-53 Account locking" "Account lock/suspension mechanism found"
else
  record "WARN" "P-53 Account locking" "No account lock mechanism for brute force protection"
fi

email_change_auth=$(grep -rn --include="*.java" \
  "changeEmail\|updateEmail\|change_email\|update_email" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$email_change_auth" ]]; then
  has_2fa=$(echo "$email_change_auth" | grep -i "2fa\|verify\|code\|auth\|confirm")
  if [[ -n "$has_2fa" ]]; then
    record "PASS" "P-53 Email change auth" "Email changes require verification"
  else
    record "WARN" "P-53 Email change auth" "Email changes may not require 2FA verification"
  fi
fi
