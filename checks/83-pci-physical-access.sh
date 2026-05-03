#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-83
name: Physical Access Evidence
description: Verifies physical security docs, badge system references, data center documentation.
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
frameworks: PCI-DSS:4.0:9.1, PCI-DSS:4.0:9.2, SOC2:TSC-2017:CC6.4, ISO-27001:2022:7.1, NIST-CSF:2.0:PR.AC-2, CIS-v8:13.10
PRESTON_META


# P-83: PCI-DSS Requirement 9 — Physical Access Evidence
# Verifies that physical security documentation and controls are referenced.
# We can't verify badge readers from code, but we CAN verify the artifacts exist.
echo "P-83: PCI Physical Access Evidence"
SRC="${SOURCE_DIR:-.}"

# Check for physical security documentation
phys_docs=$(find "$SRC" -maxdepth 5 \( \
  -iname "*physical*security*" -o -iname "*data*center*" -o -iname "*facility*" \
  -o -iname "*badge*" -o -iname "*visitor*" -o -iname "*access*control*policy*" \
  -o -iname "*clean*desk*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -5)

# Check for compliance attestation directory
compliance_dir=$(find "$SRC" -maxdepth 2 -type d -iname "compliance" 2>/dev/null | head -1)

# Check for physical access references in code (badge system, visitor management)
phys_code=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" \
  "badge\|visitor.*log\|physical.*access\|data.center\|colo\|rack.*unit\|environmental.*monitor" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)

found=0
[[ -n "$phys_docs" ]] && found=$((found + 1))
[[ -n "$compliance_dir" ]] && found=$((found + 1))
[[ -n "$phys_code" ]] && found=$((found + 1))

if [[ $found -ge 2 ]]; then
  record "PASS" "P-83 Physical access evidence" "Physical security documentation and/or references found"
elif [[ $found -ge 1 ]]; then
  record "WARN" "P-83 Physical access evidence" "Partial physical security evidence — add compliance/ directory with physical access policy" "$(echo "$phys_code" | head -10)"
else
  record "WARN" "P-83 Physical access evidence" "No physical security evidence — create compliance/physical-access-policy.md (PCI-DSS Req 9)" "$(echo "$phys_code" | head -10)"
fi
