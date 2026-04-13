#!/bin/bash
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
  record "WARN" "P-83 Physical access evidence" "Partial physical security evidence — add compliance/ directory with physical access policy"
else
  record "WARN" "P-83 Physical access evidence" "No physical security evidence — create compliance/physical-access-policy.md (PCI-DSS Req 9)"
fi
