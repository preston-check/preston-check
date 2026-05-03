#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-17
name: Secure Random
description: Checks for java.util.Random instead of SecureRandom.
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
frameworks: PCI-DSS:4.0:3.6.1, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-1, CIS-v8:3.11
PRESTON_META


# P-17: Secure randomness
# Financial systems must use SecureRandom, not Random, for all security-critical
# operations: tokens, codes, IDs, keys, nonces.

echo "P-17: Secure Randomness"

SRC="${SOURCE_DIR:-.}"

# Check for java.util.Random in security-sensitive contexts
insecure_random=$(grep -rn --include="*.java" \
  "new Random()\|java.util.Random\|Math.random()" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|SecureRandom" \
  | head -10)

if [[ -z "$insecure_random" ]]; then
  record "PASS" "P-17 Secure randomness" "No java.util.Random or Math.random() found"
else
  count=$(echo "$insecure_random" | wc -l)
  record "WARN" "P-17 Secure randomness" "$count uses of insecure Random (should be SecureRandom)" "$(echo "$insecure_random" | head -10)"
fi

# Check that SecureRandom IS used somewhere
secure_random=$(grep -rn --include="*.java" \
  "SecureRandom" \
  "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -3)

if [[ -n "$secure_random" ]]; then
  record "PASS" "P-17 SecureRandom present" "SecureRandom used in Common module"
else
  record "WARN" "P-17 SecureRandom present" "SecureRandom not found in Common — check other modules" "$(echo "$secure_random" | head -10)"
fi
