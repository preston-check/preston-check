#!/bin/bash
# P-63: Supply Chain Risk Management — NIST GV.SC, CIS 15
# Checks for SBOM generation, vendor assessment, third-party audit trail.
echo "P-63: Supply Chain Risk"
SRC="${SOURCE_DIR:-.}"

# Check for SBOM generation (CycloneDX, SPDX)
sbom=$(find "$SRC" -maxdepth 3 \( \
  -name "bom.xml" -o -name "bom.json" -o -name "sbom*" -o -name "*.spdx*" \
  -o -name "cyclonedx*" \) 2>/dev/null | head -3)
sbom_plugin=$(grep -rn --include="pom.xml" --include="package.json" \
  "cyclonedx\|spdx\|sbom" "$SRC" 2>/dev/null | head -3)
if [[ -n "$sbom" || -n "$sbom_plugin" ]]; then
  record "PASS" "P-63 SBOM generation" "Software Bill of Materials generation configured"
else
  record "WARN" "P-63 SBOM generation" "No SBOM generation configured (CycloneDX, SPDX recommended)"
fi

# Check for dependency lock files
lock_files=0
[[ -f "$SRC/package-lock.json" || -f "$SRC/yarn.lock" || -f "$SRC/pnpm-lock.yaml" ]] && lock_files=$((lock_files + 1))
mvn_wrapper=$(find "$SRC" -maxdepth 1 -name "mvnw" -o -name ".mvn" 2>/dev/null | head -1)
[[ -n "$mvn_wrapper" ]] && lock_files=$((lock_files + 1))
if [[ $lock_files -gt 0 ]]; then
  record "PASS" "P-63 Dependency locking" "Dependency lock files present"
else
  record "WARN" "P-63 Dependency locking" "No dependency lock files found"
fi

# Check for vendor/third-party documentation
vendor_docs=$(find "$SRC" -maxdepth 4 \( \
  -iname "*vendor*security*" -o -iname "*third*party*" -o -iname "*supplier*" \
  \) -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -3)
if [[ -n "$vendor_docs" ]]; then
  record "PASS" "P-63 Vendor assessment" "Vendor security documentation found"
else
  record "WARN" "P-63 Vendor assessment" "No vendor security assessment documentation found"
fi
