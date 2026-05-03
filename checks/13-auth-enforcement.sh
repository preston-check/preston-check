#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-13
name: Auth Enforcement
description: Checks controllers for missing authentication/JWT verification.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:7.2, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.3, OWASP-API:2023:API1:2023, CIS-v8:6.8
PRESTON_META

# P-13: Authentication enforcement on all endpoints
# Every non-public endpoint must require authentication. No endpoint should
# be accidentally exposed without auth.

echo "P-13: Authentication Enforcement"

SRC="${SOURCE_DIR:-.}"

# Check for controllers without auth enforcement
unprotected=$(grep -rln --include="$SRC_EXT" \
  "@Controller\|@RestController\|http\.Handle\|router\.Handle\|func.*Handler" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go" \
  | while read f; do
    if ! grep -q "$AUTH_ANNOTATION" "$f" 2>/dev/null; then
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
anon=$(grep -rn --include="$SRC_EXT" \
  "IS_ANONYMOUS\|permitAll\|@Secured.*isAnonymous\|PublicEndpoint\|NoAuth" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -10)

if [[ -n "$anon" ]]; then
  count=$(echo "$anon" | wc -l)
  record "WARN" "P-13 Anonymous endpoints" "$count publicly accessible endpoints (review intentionality)"
fi

# Check for JWT signature verification
jwt_verify=$(grep -rn --include="$SRC_EXT" \
  "$JWT_VERIFY_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -5)

if [[ -n "$jwt_verify" ]]; then
  record "PASS" "P-13 JWT verification" "JWT signature verification found"
else
  record "FAIL" "P-13 JWT verification" "No JWT signature verification found"
fi
