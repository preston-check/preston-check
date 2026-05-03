#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-494
name: Go Context Cancellation on HTTP and DB Calls
description: Detects Go HTTP client and DB query calls without context.Context cancellation. Without cancellation, slow upstreams can pin goroutines indefinitely, causing accumulating goroutine leaks and resource exhaustion under load.
category: code-scan
severity: medium
languages: go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.IP, CWE:400
cwe: 400
false_positive_rate: medium
performance_class: fast
origin: Go idioms — context.Context cancellation is the standard timeout mechanism; absence is a recurring production-incident root cause.
PRESTON_META

echo "P-494: Go Context Cancellation"

SRC="${SOURCE_DIR:-.}"
go_count=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$go_count" -eq 0 ]] && { record "SKIP" "P-494 Go context" "No Go files found"; return 0 2>/dev/null || true; }

http_no_ctx=$(grep -rn --include="*.go" -E "http\.Get\(|http\.Post\(" "$SRC" 2>/dev/null | grep -vE "/vendor/|_test\.go" | head -10 || true)
db_no_ctx=$(grep -rn --include="*.go" -E "\.Query\(\"|\.Exec\(\"|\.QueryRow\(\"" "$SRC" 2>/dev/null | grep -vE "/vendor/|_test\.go|QueryContext|ExecContext|QueryRowContext" | head -10 || true)
total=0
[[ -n "$http_no_ctx" ]] && total=$((total + $(echo "$http_no_ctx" | wc -l | tr -d ' ')))
[[ -n "$db_no_ctx" ]] && total=$((total + $(echo "$db_no_ctx" | wc -l | tr -d ' ')))
[[ $total -gt 0 ]] && record "WARN" "P-494 Go context" "$total HTTP/DB call(s) without context.Context cancellation" \
  || record "PASS" "P-494 Go context" "No non-context HTTP/DB calls detected"
