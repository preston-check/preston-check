#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-35
name: Database Encryption
description: Checks SSL enforcement, SELECT * overfetching.
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
frameworks: PCI-DSS:4.0:3.5, PCI-DSS:4.0:8.6, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.24, ISO-27001:2022:8.25, CIS-v8:3.11
PRESTON_META

# P-35: Database Encryption & Access Control
echo "P-35: Database Encryption"
SRC="${SOURCE_DIR:-.}"

db_ssl=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.java" \
  "jdbc.*url\|datasource.*url\|DB_HOST\|DriverManager.getConnection" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#" | head -5)
ssl_enforced=$(echo "$db_ssl" | grep -c "ssl\|sslmode\|useSSL\|requireSSL" 2>/dev/null)
if [[ $ssl_enforced -gt 0 ]]; then
  record "PASS" "P-35 DB SSL" "Database SSL enforcement found"
else
  record "WARN" "P-35 DB SSL" "No SSL enforcement on database connections"
fi

select_star=$(grep -rn --include="*.java" \
  '"SELECT \*\|"select \*' "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|count\|COUNT\|migration\|-- " | wc -l)
if [[ $select_star -lt 5 ]]; then
  record "PASS" "P-35 No SELECT *" "Minimal SELECT * usage ($select_star instances)"
else
  record "WARN" "P-35 SELECT *" "$select_star SELECT * queries — may overfetch sensitive data"
fi
