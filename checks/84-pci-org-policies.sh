#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-84
name: Organizational Policies
description: Verifies security policy, acceptable use, risk assessment, training, vendor mgmt.
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
frameworks: PCI-DSS:4.0:12.1, PCI-DSS:4.0:12.6, SOC2:TSC-2017:CC1.1, ISO-27001:2022:5.1, NIST-CSF:2.0:GV.PO-1, CIS-v8:14.1
PRESTON_META


# P-84: PCI-DSS Requirement 12 — Organizational Security Policies
# Verifies that security governance documentation exists and is maintained.
echo "P-84: PCI Organizational Policies"
SRC="${SOURCE_DIR:-.}"

required=0
found=0

# Information Security Policy
required=$((required + 1))
isp=$(find "$SRC" -maxdepth 5 \( -iname "*information*security*policy*" -o -iname "*infosec*policy*" -o -iname "*security*policy*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$isp" ]] && found=$((found + 1))

# Acceptable Use Policy
required=$((required + 1))
aup=$(find "$SRC" -maxdepth 5 -iname "*acceptable*use*" -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$aup" ]] && found=$((found + 1))

# Risk Assessment
required=$((required + 1))
risk=$(find "$SRC" -maxdepth 5 \( -iname "*risk*assessment*" -o -iname "*risk*register*" -o -iname "*threat*model*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$risk" ]] && found=$((found + 1))

# Security Awareness Training evidence
required=$((required + 1))
training=$(find "$SRC" -maxdepth 5 \( -iname "*security*training*" -o -iname "*awareness*training*" -o -iname "*security*awareness*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
training_code=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "training\|phishing.*sim\|security.*awareness\|knowbe4\|proofpoint.*training" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -1)
[[ -n "$training" || -n "$training_code" ]] && found=$((found + 1))

# Vendor/Third-party management
required=$((required + 1))
vendor=$(find "$SRC" -maxdepth 5 \( -iname "*vendor*management*" -o -iname "*third*party*risk*" -o -iname "*supplier*assessment*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$vendor" ]] && found=$((found + 1))

# PCI Scope documentation
required=$((required + 1))
scope=$(find "$SRC" -maxdepth 5 \( -iname "*pci*scope*" -o -iname "*cardholder*data*flow*" -o -iname "*cde*boundary*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$scope" ]] && found=$((found + 1))

if [[ $found -ge 5 ]]; then
  record "PASS" "P-84 Org policies" "$found/$required organizational security documents found"
elif [[ $found -ge 3 ]]; then
  record "WARN" "P-84 Org policies" "$found/$required — need: security policy, acceptable use, risk assessment, training evidence, vendor mgmt, PCI scope"
else
  record "WARN" "P-84 Org policies" "Only $found/$required — create compliance/ directory with required policy documents (PCI-DSS Req 12)"
fi
