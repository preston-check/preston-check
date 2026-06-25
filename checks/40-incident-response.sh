#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-40
name: Incident Response
description: Checks session revocation, IR documentation.
category: compliance-evidence
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:12.10, SOC2:TSC-2017:CC7.3, SOC2:TSC-2017:CC7.4, ISO-27001:2022:5.24, ISO-27001:2022:5.26, NIST-CSF:2.0:RS.RP-1, CIS-v8:17.1
PRESTON_META


# P-40: Incident Response Readiness
echo "P-40: Incident Response"
SRC="${SOURCE_DIR:-.}"
bulk_revoke=$(grep -rn --include="*.java" "killAllSessions\|revokeAll\|clearAll.*session\|deleteSessionCache\|BlacklistCheck" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$bulk_revoke" ]]; then record "PASS" "P-40 Session revocation" "Bulk session revocation capability found"; else record "WARN" "P-40 Session revocation" "No bulk session revocation mechanism"; fi
ir_docs=$(find "$SRC/docs" -maxdepth 2 \( -name "*SECURITY*" -o -name "*HACK*" -o -name "*incident*" -o -name "*playbook*" -o -name "*FORENSIC*" \) 2>/dev/null)
if [[ -n "$ir_docs" ]]; then count=$(echo "$ir_docs" | wc -l); record "PASS" "P-40 IR documentation" "$count security/incident response documents found"; else record "WARN" "P-40 IR documentation" "No incident response documentation"; fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "killAllSessions|revokeAll|clearAll.*session|deleteSessionCache|BlacklistCheck" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-40 Session Revocation (Go)" "Bulk session revocation capability found in Go code"
  else
    record "WARN" "P-40 Session Revocation (Go)" "No bulk session revocation mechanism found in Go code"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "kill_all_sessions|revoke_all|clear_all_session|delete_session_cache|blacklist_check" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-40 Session Revocation (Rust)" "Bulk session revocation capability found in Rust code"
  else
    record "WARN" "P-40 Session Revocation (Rust)" "No bulk session revocation mechanism found in Rust code"
  fi
fi
