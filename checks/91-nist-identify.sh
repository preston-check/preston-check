#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-91
name: NIST Identify
description: Verifies asset inventory, risk assessment, improvement tracking.
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
frameworks: CIS-v8:1.1
PRESTON_META


# P-91: NIST CSF 2.0 Identify Function — Asset Management & Risk Assessment
echo "P-91: NIST CSF Identify"
SRC="${SOURCE_DIR:-.}"

# ID.AM — Asset Management (software inventory, network architecture)
asset_mgmt=$(grep -rn --include="*.md" --include="*.yml" --include="*.json" --include="*.xml" \
  "asset.*inventory\|cmdb\|service.*catalog\|services\.list\|services\.yml\|architecture.*diagram" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
asset_doc=$(find "$SRC" -maxdepth 5 \( -iname "*asset*inventory*" -o -iname "*service*catalog*" -o -iname "*architecture*" -o -iname "services.list" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
if [[ -n "$asset_mgmt" || -n "$asset_doc" ]]; then
  record "PASS" "P-91 Asset management" "Asset inventory/service catalog references found"
else
  record "WARN" "P-91 Asset management" "No asset inventory or service catalog — create services.list or architecture doc (NIST ID.AM)"
fi

# ID.RA — Risk Assessment
risk_assess=$(find "$SRC" -maxdepth 5 \( -iname "*risk*assess*" -o -iname "*threat*model*" -o -iname "*risk*register*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
risk_code=$(grep -rn --include="*.md" "risk.*score\|threat.*level\|vulnerability.*rating\|CVSS\|risk.*matrix" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
if [[ -n "$risk_assess" || -n "$risk_code" ]]; then
  record "PASS" "P-91 Risk assessment" "Risk assessment documentation found"
else
  record "WARN" "P-91 Risk assessment" "No risk assessment documentation (NIST ID.RA)"
fi

# ID.IM — Improvement
improvement=$(grep -rn --include="*.md" --include="*.yml" \
  "lessons.*learned\|post.*mortem\|retrospective\|improvement.*plan\|security.*roadmap\|remediation.*track" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -n "$improvement" ]]; then
  record "PASS" "P-91 Improvement" "Improvement/lessons-learned patterns found"
else
  record "WARN" "P-91 Improvement" "No improvement tracking (post-mortems, lessons learned, security roadmap)"
fi
