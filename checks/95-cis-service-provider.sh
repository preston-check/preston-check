#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-95
name: CIS Service Provider and Pentest
description: Verifies vendor assessments, pentest program, vulnerability scan schedule.
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
frameworks: CIS-v8:15.1, CIS-v8:18.1, ISO-27001:2022:5.19, NIST-CSF:2.0:ID.RA-1
PRESTON_META


# P-95: CIS Control 15 — Service Provider Management + CIS Control 18 — Pentest Program
echo "P-95: CIS Service Provider & Pentest"
SRC="${SOURCE_DIR:-.}"

# CIS 15 — Service provider security assessment
vendor_assess=$(find "$SRC" -maxdepth 5 \( \
  -iname "*vendor*assess*" -o -iname "*vendor*security*" -o -iname "*third*party*risk*" \
  -o -iname "*supplier*due*diligence*" -o -iname "*service*provider*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -3)
soc_reports=$(grep -rn --include="*.md" \
  "SOC.*2.*report\|SOC.*report\|vendor.*audit\|annual.*review\|due.*diligence" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -n "$vendor_assess" || -n "$soc_reports" ]]; then
  record "PASS" "P-95 Service provider mgmt" "Vendor security assessment evidence found"
else
  record "WARN" "P-95 Service provider mgmt" "No vendor security assessment evidence (CIS Control 15)" "$(echo "$soc_reports" | head -10)"
fi

# CIS 18 — Penetration testing program
pentest_program=$(find "$SRC" -maxdepth 5 \( \
  -iname "*pentest*program*" -o -iname "*penetration*test*schedule*" \
  -o -iname "*red*team*" -o -iname "*bug*bounty*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
pentest_evidence=$(find "$SRC" -maxdepth 5 \( \
  -iname "*pentest*report*" -o -iname "*penetration*test*result*" \
  -o -iname "*vulnerability*assessment*" -o -iname "*security*assessment*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -3)
if [[ -n "$pentest_program" || -n "$pentest_evidence" ]]; then
  count=0
  [[ -n "$pentest_program" ]] && count=$((count + 1))
  [[ -n "$pentest_evidence" ]] && count=$((count + 1))
  record "PASS" "P-95 Pentest program" "Penetration testing evidence found"
else
  record "WARN" "P-95 Pentest program" "No penetration testing program evidence (CIS Control 18)" "$(echo "$pentest_evidence" | head -10)"
fi

# Check for vulnerability management schedule
vuln_schedule=$(grep -rn --include="*.md" --include="*.yml" \
  "quarterly.*scan\|monthly.*scan\|annual.*pentest\|vulnerability.*schedule\|scan.*cadence" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
if [[ -n "$vuln_schedule" ]]; then
  record "PASS" "P-95 Vuln scan schedule" "Vulnerability scanning schedule documented"
else
  record "WARN" "P-95 Vuln scan schedule" "No vulnerability scanning schedule — document quarterly ASV scans and annual pentests" "$(echo "$vuln_schedule" | head -10)"
fi
