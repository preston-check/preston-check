#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-35
name: Database Encryption
description: Checks SSL enforcement, SELECT * overfetching.
category: code-scan
severity: high
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:3.5, PCI-DSS:4.0:8.6, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.24, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-1, CIS-v8:3.11
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
  record "WARN" "P-35 DB SSL" "No SSL enforcement on database connections" "$(echo "$db_ssl" | head -10)"
fi

select_star=$(grep -rn --include="*.java" \
  '"SELECT \*\|"select \*' "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|count\|COUNT\|migration\|-- " | wc -l)
if [[ $select_star -lt 5 ]]; then
  record "PASS" "P-35 No SELECT *" "Minimal SELECT * usage ($select_star instances)"
else
  record "WARN" "P-35 SELECT *" "$select_star SELECT * queries — may overfetch sensitive data" "$(echo "$select_star" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "db\.Query|db\.Exec|sqlx\.Get|gorm\.Where" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-35 Raw DB Queries (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-35 Raw DB Queries (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "sqlx::query|diesel::sql_query|tokio_postgres|\.query\(" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-35 Raw DB Queries (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-35 Raw DB Queries (Rust)" "No issues found in Rust files"
  fi
fi
