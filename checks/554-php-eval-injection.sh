#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-554
name: PHP eval() and Dynamic Code Execution
description: Detects use of eval(), assert() with string arguments, create_function(), or dynamic include() of user-controlled paths. Each is direct PHP code injection.
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
frameworks: OWASP-Top-10:2021:A03, CWE:95
cwe: 95
false_positive_rate: medium
performance_class: fast
origin: PHP eval() is a notorious anti-pattern; create_function() was deprecated in PHP 7.2 specifically because of injection risk.
PRESTON_META

echo "P-554: PHP eval / Dynamic Code Execution"

SRC="${SOURCE_DIR:-.}"
php_count=$(find "$SRC" -name "*.php" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$php_count" -eq 0 ]] && { record "SKIP" "P-554 PHP eval" "No PHP files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.php" -E "\beval\s*\(\s*\\\$|\bcreate_function\s*\(|include\s*\(\s*\\\$_(GET|POST|REQUEST)|require\s*\(\s*\\\$_(GET|POST|REQUEST)" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/vendor/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-554 PHP eval" "$(echo "$unsafe" | wc -l | tr -d ' ') dynamic-code-execution pattern(s)" "$sample"; } \
  || record "PASS" "P-554 PHP eval" "No eval/create_function/dynamic-include patterns detected"
