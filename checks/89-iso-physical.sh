#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-89
name: ISO Physical Controls
description: Verifies data center docs, equipment security, environmental monitoring.
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
frameworks: ISO-27001:2022:7.1, ISO-27001:2022:7.14
PRESTON_META


# P-89: ISO 27001 Physical Controls (A.7.x) Evidence
# Checks for data center docs, environmental monitoring, equipment management.
echo "P-89: ISO 27001 Physical Controls"
SRC="${SOURCE_DIR:-.}"

found=0

# A.7.1-7.4 — Physical security perimeters, entry controls
phys=$(find "$SRC" -maxdepth 5 \( \
  -iname "*physical*security*" -o -iname "*access*control*policy*" \
  -o -iname "*data*center*" -o -iname "*colo*" -o -iname "*facility*security*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
[[ -n "$phys" ]] && found=$((found + 1))

# A.7.8-7.9 — Equipment security (cloud infrastructure docs)
equip=$(grep -rn --include="*.md" --include="*.yml" --include="*.tf" \
  "hardware.*security\|server.*room\|equipment.*disposal\|media.*sanitiz\|aws.*region\|data.*center.*tier" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
[[ -n "$equip" ]] && found=$((found + 1))

# A.7.11-7.13 — Supporting utilities, cabling, maintenance
infra=$(grep -rn --include="*.md" --include="*.yml" --include="*.tf" \
  "ups\|power.*redundan\|cooling\|fire.*suppress\|environment.*monitor\|humidity\|temperature.*alert" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
cloud_infra=$(grep -rn --include="*.yml" --include="*.tf" --include="*.json" \
  "aws.*ec2\|vpc\|subnet\|availability.*zone\|region.*us-east" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -1)
[[ -n "$infra" || -n "$cloud_infra" ]] && found=$((found + 1))

if [[ $found -ge 2 ]]; then
  record "PASS" "P-89 ISO physical controls" "$found/3 physical control evidence found (cloud infrastructure counts)"
elif [[ $found -ge 1 ]]; then
  record "WARN" "P-89 ISO physical controls" "$found/3 — for cloud: document AWS region selection, VPC architecture, environmental controls via shared responsibility" "$(echo "$cloud_infra" | head -10)"
else
  record "WARN" "P-89 ISO physical controls" "No physical control evidence — document cloud infrastructure security (AWS shared responsibility model)" "$(echo "$cloud_infra" | head -10)"
fi
