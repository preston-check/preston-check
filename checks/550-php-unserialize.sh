#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-550
name: PHP unserialize() on Untrusted Input
description: Detects PHP unserialize() calls on user-controlled input. PHP object injection via crafted serialized payloads is a classic RCE class; modern PHP code should use json_decode() instead.
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
frameworks: OWASP-Top-10:2021:A08, CWE:502
cwe: 502
false_positive_rate: medium
performance_class: fast
origin: PHP object injection via unserialize() is one of the oldest and most exploited PHP vulnerability classes.
PRESTON_META

echo "P-550: PHP unserialize"

SRC="${SOURCE_DIR:-.}"
php_count=$(find "$SRC" -name "*.php" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$php_count" -eq 0 ]] && { record "SKIP" "P-550 PHP unserialize" "No PHP files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.php" -E "\bunserialize\s*\(\s*\\\$_(GET|POST|REQUEST|COOKIE)" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/vendor/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-550 PHP unserialize" "$(echo "$unsafe" | wc -l | tr -d ' ') unserialize() call(s) on user input" "$sample"; } \
  || record "PASS" "P-550 PHP unserialize" "No unserialize() on \$_GET/\$_POST/\$_REQUEST/\$_COOKIE detected"
