#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-551
name: PHP Weak Password Hashing
description: Detects use of md5(), sha1(), or unsalted hashing for password storage. PHP code should use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID.
category: code-scan
severity: critical
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A02, PCI-DSS:4.0:8.3.1, CWE:328
cwe: 328
false_positive_rate: medium
performance_class: fast
origin: Legacy PHP password storage was a common breach root cause throughout the 2010s; password_hash() introduced in PHP 5.5 to fix it.
PRESTON_META

echo "P-551: PHP Weak Password Hashing"

SRC="${SOURCE_DIR:-.}"
php_count=$(find "$SRC" -name "*.php" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$php_count" -eq 0 ]] && { record "SKIP" "P-551 PHP weak hash" "No PHP files found"; return 0 2>/dev/null || true; }

weak=$(grep -rn --include="*.php" -E "(md5|sha1)\s*\(\s*\\\$(password|pwd|passwd|user_password)" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/vendor/" || true)
[[ -n "$weak" ]] && { sample=$(echo "$weak" | head -10); record "FAIL" "P-551 PHP weak hash" "$(echo "$weak" | wc -l | tr -d ' ') md5/sha1 password hashing call(s)" "$sample"; } \
  || record "PASS" "P-551 PHP weak hash" "No md5/sha1 password hashing detected"
