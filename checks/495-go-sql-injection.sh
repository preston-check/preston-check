#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-495
name: Go SQL Injection via String Concatenation
description: Detects Go DB query calls that concatenate variables into SQL strings using fmt.Sprintf or '+'. Parameterized queries (placeholders, not string interpolation) are required to prevent SQL injection.
category: code-scan
severity: critical
languages: go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A03, PCI-DSS:4.0:6.5.1, CWE:89
cwe: 89
false_positive_rate: medium
performance_class: fast
origin: SQL injection in Go code via string interpolation in db.Query is an evergreen vulnerability class.
PRESTON_META

echo "P-495: Go SQL Injection Patterns"

SRC="${SOURCE_DIR:-.}"
go_count=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$go_count" -eq 0 ]] && { record "SKIP" "P-495 Go SQL injection" "No Go files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.go" -E "(Query|Exec|QueryRow)Context?\s*\(\s*[^,]*fmt\.Sprintf\s*\(\s*[\"\`][^\`\"]*(SELECT|INSERT|UPDATE|DELETE)" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/vendor/|_test\.go" || true)
if [[ -n "$unsafe" ]]; then
  sample=$(echo "$unsafe" | head -10)
  record "FAIL" "P-495 Go SQL injection" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe SQL string interpolation pattern(s)" "$sample"
else
  record "PASS" "P-495 Go SQL injection" "No fmt.Sprintf-based SQL string interpolation detected"
fi
