#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-552
name: PHP SQL Injection via Concatenation
description: Detects mysqli_query, mysql_query, or PDO->query calls with string-concatenated user input. Use prepared statements (PDO->prepare with bindParam, or mysqli prepare) instead.
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
frameworks: OWASP-Top-10:2021:A03, PCI-DSS:4.0:6.5.1, CWE:89
cwe: 89
false_positive_rate: medium
performance_class: fast
origin: Classic PHP vulnerability class; persists in legacy code despite parameterized-query availability since PHP 5.
PRESTON_META

echo "P-552: PHP SQL Injection"

SRC="${SOURCE_DIR:-.}"
php_count=$(find "$SRC" -name "*.php" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$php_count" -eq 0 ]] && { record "SKIP" "P-552 PHP SQL injection" "No PHP files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.php" -E "(mysqli?_query|->query)\s*\([^)]*\\\$_(GET|POST|REQUEST|COOKIE)" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/vendor/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-552 PHP SQL injection" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe query patterns" "$sample"; } \
  || record "PASS" "P-552 PHP SQL injection" "No string-concatenation SQL detected"
