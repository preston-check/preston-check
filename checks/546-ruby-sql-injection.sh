#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-546
name: Ruby ActiveRecord SQL Injection
description: Detects ActiveRecord queries using string interpolation in where clauses, find_by_sql, or raw SQL. Parameterized syntax (where("col = ?", val) or hash form) is required.
category: code-scan
severity: critical
languages: ruby
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
origin: rails-sqli.org documents this pattern; one of the most common Rails vulnerability classes.
PRESTON_META

echo "P-546: Ruby SQL Injection"

SRC="${SOURCE_DIR:-.}"
rb_count=$(find "$SRC" -name "*.rb" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rb_count" -eq 0 ]] && { record "SKIP" "P-546 Ruby SQL injection" "No Ruby files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.rb" -E "\.where\s*\(\s*\"[^\"]*#\{|find_by_sql\s*\(\s*\"[^\"]*#\{|order\s*\(\s*params|select\s*\(\s*\"[^\"]*#\{" "$SRC" 2>/dev/null \
  | grep -vE "/spec/|/test/|/vendor/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-546 Ruby SQL injection" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe ActiveRecord interpolation(s)" "$sample"; } \
  || record "PASS" "P-546 Ruby SQL injection" "No string-interpolation SQL detected in ActiveRecord"
