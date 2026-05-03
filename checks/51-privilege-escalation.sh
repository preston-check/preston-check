#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-51
name: Privilege Escalation
description: Checks unguarded role/permission mutations.
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
frameworks: PCI-DSS:4.0:7.2, SOC2:TSC-2017:CC6.1, SOC2:TSC-2017:CC6.3, ISO-27001:2022:8.2, ISO-27001:2022:8.3, OWASP-API:2023:API5, CIS-v8:6.8
PRESTON_META


# P-51: Privilege Escalation Prevention
# Role/permission changes must be admin-only and audited.
echo "P-51: Privilege Escalation"
SRC="${SOURCE_DIR:-.}"
role_change=$(grep -rn --include="*.java" \
  "setRole\|updateRole\|addRole\|removeRole\|setPermission\|grantPermission\|set_2fa_state\|setBlacklisted" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -5)
role_auth=$(echo "$role_change" | grep -i "admin\|@Secured\|authorize\|isAdmin\|isSuperuser\|requireRole" | head -3)
if [[ -z "$role_change" ]]; then
  record "PASS" "P-51 No unguarded role changes" "No role/permission mutation found"
elif [[ -n "$role_auth" ]]; then
  record "PASS" "P-51 Role changes guarded" "Role mutations have authorization checks"
else
  record "WARN" "P-51 Unguarded role changes" "Role/permission changes may lack admin authorization checks" "$(echo "$role_change" | head -10)"
fi
