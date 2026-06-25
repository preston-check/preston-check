#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-51
name: Privilege Escalation
description: Checks unguarded role/permission mutations.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "setRole|updateRole|addRole|removeRole|setPermission|grantPermission|hasRole|isAdmin|checkPermission|Authorize" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-51 Unguarded Role Changes (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-51 Unguarded Role Changes (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "set_role|update_role|add_role|remove_role|set_permission|grant_permission|has_role|is_admin|check_permission|authorize" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-51 Unguarded Role Changes (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-51 Unguarded Role Changes (Rust)" "No issues found in Rust files"
  fi
fi
