#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-280
name: Supply Chain
description: Supply Chain security check (see COMPLIANCE_MAPPING.md for details).
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
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

# P-280: Supply Chain Security
echo "P-280: Supply Chain Security"
SRC="${SOURCE_DIR:-.}"

# Only flag SNAPSHOT in dependency versions, not the module's own <version> tag
# A module version like 0.0.1-SNAPSHOT is normal for development; a dependency on SNAPSHOT is dangerous
snapshot=$(grep -rB3 --include="pom.xml" 'SNAPSHOT' "$SRC" 2>/dev/null | grep -B3 "SNAPSHOT" | grep "<groupId>\|<artifactId>" | grep -v "test\|Test\|target\|node_modules")
if [[ -z "$snapshot" ]]; then record "PASS" "P-280 No SNAPSHOT deps" "No SNAPSHOT dependencies in production"; else count=$(echo "$snapshot" | wc -l | tr -d ' '); record "FAIL" "P-280 No SNAPSHOT deps" "$count SNAPSHOT dependencies — non-reproducible builds"; echo "$snapshot" | head -5; fi

version_pinned=$(grep -rn --include="pom.xml" '<version>' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|SNAPSHOT\|<!--\|\${" | wc -l | tr -d ' ')
if [[ $version_pinned -gt 10 ]]; then record "PASS" "P-280 Pinned versions" "$version_pinned pinned dependency versions found"; else record "WARN" "P-280 Pinned versions" "Few pinned versions — all dependencies should have exact versions"; fi

lockfile=$(find "$SRC" -maxdepth 3 \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) 2>/dev/null | grep -v "node_modules\|target" | head -3)
if [[ -n "$lockfile" ]]; then record "PASS" "P-280 Lockfiles" "Dependency lockfiles found"; else record "WARN" "P-280 Lockfiles" "No dependency lockfiles — builds may be non-reproducible"; fi

trusted_registry=$(grep -rn --include="pom.xml" --include="*.gradle" 'repository\|<url>' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|central\|maven\|github\|<!--" | head -3)
if [[ -z "$trusted_registry" ]]; then record "PASS" "P-280 Trusted registries" "Only standard registries used"; else record "WARN" "P-280 Trusted registries" "Custom/third-party registries found — verify trust"; fi
