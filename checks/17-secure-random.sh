#!/bin/bash
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
  record "WARN" "P-17 Secure randomness" "$count uses of insecure Random (should be SecureRandom)"
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
  record "WARN" "P-17 SecureRandom present" "SecureRandom not found in Common — check other modules"
fi
