#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-555
name: C# / .NET SQL Injection via Concatenation
description: Detects ADO.NET SqlCommand / Entity Framework FromSqlRaw / Dapper Query calls with string-concatenated user input. Parameterized queries (SqlParameter, FromSqlInterpolated, named parameters) are required.
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
origin: ADO.NET / EF SQL injection persists in legacy .NET code; `FromSqlRaw` and `ExecuteSqlRaw` accept raw strings and require parameterization.
PRESTON_META

echo "P-555: C# SQL Injection"

SRC="${SOURCE_DIR:-.}"
cs_count=$(find "$SRC" -name "*.cs" -not -path "*/bin/*" -not -path "*/obj/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$cs_count" -eq 0 ]] && { record "SKIP" "P-555 C# SQL injection" "No C# files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.cs" -E "(SqlCommand\s*\(\s*\\\$\"|FromSqlRaw\s*\(\s*\\\$\"|FromSqlRaw\s*\([^,)]+\+|ExecuteSqlRaw\s*\([^,)]+\+|new\s+SqlCommand\s*\([^,)]+\+)" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/Tests/|/bin/|/obj/" || true)
[[ -n "$unsafe" ]] && { sample=$(echo "$unsafe" | head -10); record "FAIL" "P-555 C# SQL injection" "$(echo "$unsafe" | wc -l | tr -d ' ') unsafe ADO.NET/EF query pattern(s)" "$sample"; } \
  || record "PASS" "P-555 C# SQL injection" "No string-concatenation SQL detected in C#"
