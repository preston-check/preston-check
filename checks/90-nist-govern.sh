#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-90
name: NIST Govern
description: Verifies organizational context, risk strategy, roles, supply chain governance.
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
frameworks: ISO-27001:2022:5.1, ISO-27001:2022:5.4
PRESTON_META


# P-90: NIST CSF 2.0 Govern Function (GV)
# Checks for governance documentation: organizational context, risk management strategy,
# roles/responsibilities, cybersecurity policy, oversight, supply chain risk management.
echo "P-90: NIST CSF Govern"
SRC="${SOURCE_DIR:-.}"

found=0
required=5

# GV.OC — Organizational Context
org_context=$(find "$SRC" -maxdepth 5 \( \
  -iname "*business*context*" -o -iname "*organizational*context*" -o -iname "*company*overview*" \
  -o -iname "*stakeholder*" -o -iname "*mission*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$org_context" ]] && found=$((found + 1))

# GV.RM — Risk Management Strategy
risk_mgmt=$(find "$SRC" -maxdepth 5 \( \
  -iname "*risk*management*" -o -iname "*risk*appetite*" -o -iname "*risk*tolerance*" \
  -o -iname "*risk*register*" -o -iname "*risk*assessment*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$risk_mgmt" ]] && found=$((found + 1))

# GV.RR — Roles, Responsibilities, Authorities
roles=$(grep -rn --include="*.md" --include="*.yml" \
  "CISO\|security.*officer\|security.*team\|security.*committee\|DPO\|data.*protection.*officer\|compliance.*officer" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
roles_doc=$(find "$SRC" -maxdepth 5 -iname "*roles*responsib*" -not -path "*/target/*" 2>/dev/null | head -1)
[[ -n "$roles" || -n "$roles_doc" ]] && found=$((found + 1))

# GV.PO — Cybersecurity Policy
policy=$(find "$SRC" -maxdepth 5 \( -iname "*security*policy*" -o -iname "*cyber*policy*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$policy" ]] && found=$((found + 1))

# GV.SC — Supply Chain Risk Management
scm=$(find "$SRC" -maxdepth 5 \( -iname "*supply*chain*" -o -iname "*vendor*risk*" -o -iname "*sbom*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
scm_code=$(grep -rn --include="*.json" --include="*.xml" "cyclonedx\|spdx\|sbom\|bom\.xml" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
[[ -n "$scm" || -n "$scm_code" ]] && found=$((found + 1))

if [[ $found -ge 4 ]]; then
  record "PASS" "P-90 NIST Govern" "$found/$required governance evidence found"
elif [[ $found -ge 2 ]]; then
  record "WARN" "P-90 NIST Govern" "$found/$required — need: org context, risk management, roles, security policy, supply chain risk" "$(echo "$scm_code" | head -10)"
else
  record "WARN" "P-90 NIST Govern" "Only $found/$required governance evidence — create compliance/ directory with governance docs" "$(echo "$scm_code" | head -10)"
fi
