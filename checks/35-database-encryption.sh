#!/bin/bash
# P-35: Database Encryption & Access Control
echo "P-35: Database Encryption"
SRC="${SOURCE_DIR:-.}"

db_ssl=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.java" --max-count=10 \
  "jdbc.*url\|datasource.*url\|DB_HOST\|DriverManager.getConnection" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#" | head -5)
ssl_enforced=$(echo "$db_ssl" | grep -c "ssl\|sslmode\|useSSL\|requireSSL" 2>/dev/null)
if [[ $ssl_enforced -gt 0 ]]; then
  record "PASS" "P-35 DB SSL" "Database SSL enforcement found"
else
  record "WARN" "P-35 DB SSL" "No SSL enforcement on database connections"
fi

select_star=$(grep -rn --include="*.java" --max-count=15 \
  '"SELECT \*\|"select \*' "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|count\|COUNT\|migration\|-- " | wc -l)
if [[ $select_star -lt 5 ]]; then
  record "PASS" "P-35 No SELECT *" "Minimal SELECT * usage ($select_star instances)"
else
  record "WARN" "P-35 SELECT *" "$select_star SELECT * queries — may overfetch sensitive data"
fi
