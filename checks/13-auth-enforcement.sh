#!/bin/bash
# P-13: Authentication enforcement on all endpoints
# Every non-public endpoint must require authentication. No endpoint should
# be accidentally exposed without auth.

echo "P-13: Authentication Enforcement"

SRC="${SOURCE_DIR:-.}"

# Check for controllers without @Secured or auth filter
unprotected=$(grep -rln --include="*.java" \
  "@Controller\|@RestController" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" \
  | while read f; do
    if ! grep -q "@Secured\|@RolesAllowed\|authenticate\|AuthEnforcementFilter\|IS_AUTHENTICATED\|IS_ANONYMOUS" "$f" 2>/dev/null; then
      echo "$f"
    fi
  done)

if [[ -z "$unprotected" ]]; then
  record "PASS" "P-13 Auth on controllers" "All controllers have authentication annotations"
else
  count=$(echo "$unprotected" | wc -l)
  record "WARN" "P-13 Auth on controllers" "$count controllers may lack auth enforcement"
fi

# Check for IS_ANONYMOUS endpoints (intentionally public)
anon=$(grep -rn --include="*.java" \
  --max-count=10 "IS_ANONYMOUS\|permitAll\|@Secured.*isAnonymous" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -10)

if [[ -n "$anon" ]]; then
  count=$(echo "$anon" | wc -l)
  record "WARN" "P-13 Anonymous endpoints" "$count publicly accessible endpoints (review intentionality)"
fi

# Check for JWT signature verification
jwt_verify=$(grep -rn --include="*.java" \
  --max-count=5 "JWT.require\|JWTVerifier\|verify.*token\|verifyToken" \
  "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -5)

if [[ -n "$jwt_verify" ]]; then
  record "PASS" "P-13 JWT verification" "JWT signature verification found"
else
  record "FAIL" "P-13 JWT verification" "No JWT signature verification found"
fi
