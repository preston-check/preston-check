#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-40
name: Incident Response
description: Checks session revocation, IR documentation.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:12.10, SOC2:TSC-2017:CC7.3, SOC2:TSC-2017:CC7.4, ISO-27001:2022:5.24, ISO-27001:2022:5.26, CIS-v8:17.1
PRESTON_META

# P-40: Incident Response Readiness
echo "P-40: Incident Response"
SRC="${SOURCE_DIR:-.}"
bulk_revoke=$(grep -rn --include="*.java" "killAllSessions\|revokeAll\|clearAll.*session\|deleteSessionCache\|BlacklistCheck" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$bulk_revoke" ]]; then record "PASS" "P-40 Session revocation" "Bulk session revocation capability found"; else record "WARN" "P-40 Session revocation" "No bulk session revocation mechanism"; fi
ir_docs=$(find "$SRC/docs" -maxdepth 2 \( -name "*SECURITY*" -o -name "*HACK*" -o -name "*incident*" -o -name "*playbook*" -o -name "*FORENSIC*" \) 2>/dev/null)
if [[ -n "$ir_docs" ]]; then count=$(echo "$ir_docs" | wc -l); record "PASS" "P-40 IR documentation" "$count security/incident response documents found"; else record "WARN" "P-40 IR documentation" "No incident response documentation"; fi
