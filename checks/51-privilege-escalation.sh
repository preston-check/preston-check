#!/bin/bash
# P-51: Privilege Escalation Prevention
# Role/permission changes must be admin-only and audited.
echo "P-51: Privilege Escalation"
SRC="${SOURCE_DIR:-.}"
role_change=$(grep -rn --include="*.java" --max-count=10 \
  "setRole\|updateRole\|addRole\|removeRole\|setPermission\|grantPermission\|set_2fa_state\|setBlacklisted" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -5)
role_auth=$(echo "$role_change" | grep -i "admin\|@Secured\|authorize\|isAdmin\|isSuperuser\|requireRole" | head -3)
if [[ -z "$role_change" ]]; then
  record "PASS" "P-51 No unguarded role changes" "No role/permission mutation found"
elif [[ -n "$role_auth" ]]; then
  record "PASS" "P-51 Role changes guarded" "Role mutations have authorization checks"
else
  record "WARN" "P-51 Unguarded role changes" "Role/permission changes may lack admin authorization checks"
fi
