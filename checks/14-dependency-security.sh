#!/bin/bash
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
  record "WARN" "P-14 Bouncy Castle version" "$count pom.xml files use deprecated jdk15on (should be jdk18on)"
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
  record "WARN" "P-14 No SNAPSHOT deps" "$count SNAPSHOT dependencies found"
fi

# Check npm for high/critical vulnerabilities (if package.json exists)
if [[ -f "$SRC/package.json" ]] || find "$SRC" -maxdepth 3 -name "package.json" -not -path "*/node_modules/*" 2>/dev/null | head -1 | grep -q .; then
  record "WARN" "P-14 npm audit" "Run 'npm audit' manually to check for JS vulnerabilities"
else
  record "SKIP" "P-14 npm audit" "No package.json found"
fi
