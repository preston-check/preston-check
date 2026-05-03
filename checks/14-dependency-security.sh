#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-14
name: Dependency Security
description: Checks for vulnerable libraries, SNAPSHOT dependencies.
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
frameworks: PCI-DSS:4.0:6.3.2, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, OWASP-API:2023:API10, NIST-CSF:2.0:ID.AM-2, CIS-v8:16.3
PRESTON_META


# P-14: Dependency security
# Check for known vulnerable dependencies, outdated libraries,
# and insecure dependency configurations.

echo "P-14: Dependency Security"

SRC="${SOURCE_DIR:-.}"

# Check for known vulnerable library versions in pom.xml files
bouncy_old=$(grep -rn --include="pom.xml" \
  "bcpkix-jdk15on\|bcprov-jdk15on" \
  "$SRC" 2>/dev/null \
  | grep -v "target\|node_modules" \
  | head -5)

if [[ -z "$bouncy_old" ]]; then
  record "PASS" "P-14 Bouncy Castle version" "No deprecated bcpkix-jdk15on found"
else
  count=$(echo "$bouncy_old" | wc -l)
  record "WARN" "P-14 Bouncy Castle version" "$count pom.xml files use deprecated jdk15on (should be jdk18on)" "$(echo "$bouncy_old" | head -10)"
fi

# Check for SNAPSHOT dependencies in non-test poms
snapshots=$(grep -rn --include="pom.xml" \
  "SNAPSHOT" \
  "$SRC" 2>/dev/null \
  | grep -v "target\|node_modules\|test\|<version>.*SNAPSHOT.*</version>" \
  | grep "<version>" \
  | head -5)

if [[ -z "$snapshots" ]]; then
  record "PASS" "P-14 No SNAPSHOT deps" "No SNAPSHOT dependencies in production"
else
  count=$(echo "$snapshots" | wc -l)
  record "WARN" "P-14 No SNAPSHOT deps" "$count SNAPSHOT dependencies found" "$(echo "$snapshots" | head -10)"
fi

# Check npm for high/critical vulnerabilities (if package.json exists)
if [[ -f "$SRC/package.json" ]] || find "$SRC" -maxdepth 3 -name "package.json" -not -path "*/node_modules/*" 2>/dev/null | head -1 | grep -q .; then
  record "WARN" "P-14 npm audit" "Run 'npm audit' manually to check for JS vulnerabilities" "$(echo "$snapshots" | head -10)"
else
  record "SKIP" "P-14 npm audit" "No package.json found"
fi
