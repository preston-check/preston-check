#!/bin/bash
# P-40: Incident Response Readiness
echo "P-40: Incident Response"
SRC="${SOURCE_DIR:-.}"
bulk_revoke=$(grep -rn --include="*.java" --max-count=5 "killAllSessions\|revokeAll\|clearAll.*session\|deleteSessionCache\|BlacklistCheck" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$bulk_revoke" ]]; then record "PASS" "P-40 Session revocation" "Bulk session revocation capability found"; else record "WARN" "P-40 Session revocation" "No bulk session revocation mechanism"; fi
ir_docs=$(find "$SRC/docs" -maxdepth 2 \( -name "*SECURITY*" -o -name "*HACK*" -o -name "*incident*" -o -name "*playbook*" -o -name "*FORENSIC*" \) 2>/dev/null | head -3)
if [[ -n "$ir_docs" ]]; then count=$(echo "$ir_docs" | wc -l); record "PASS" "P-40 IR documentation" "$count security/incident response documents found"; else record "WARN" "P-40 IR documentation" "No incident response documentation"; fi
