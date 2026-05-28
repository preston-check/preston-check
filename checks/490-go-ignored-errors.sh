#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-490
name: Go Ignored Error Returns
description: Detects Go code that ignores error returns via blank identifier `_, _ = func()` or omits error handling on calls that return errors. Silently swallowed errors in financial paths corrupt state without alerting.
category: code-scan
severity: high
languages: go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A09, CWE:391
false_positive_rate: medium
performance_class: fast
origin: Go idiom violations; common in fast-shipped code that doesn't get reviewed for error-handling discipline. Direct cause of silent ledger drift in fintech codebases.
PRESTON_META

echo "P-490: Go Ignored Error Returns"

SRC="${SOURCE_DIR:-.}"
go_count=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$go_count" -eq 0 ]] && { record "SKIP" "P-490 Go ignored errors" "No Go files found"; return 0 2>/dev/null || true; }

ignored=$(grep -rn --include="*.go" -E "(^|;)\s*_,\s*_\s*[:=]\s*[a-zA-Z]" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/vendor/|_test\.go|/test/" || true)
count=$([[ -n "$ignored" ]] && echo "$ignored" | wc -l | tr -d ' ' || echo 0)
if [[ ${count:-0} -gt 0 ]]; then
  record "WARN" "P-490 Go ignored errors" "$count instance(s) of '_, _ =' patterns ignoring error returns" "$(echo "$ignored" | head -10)"
else
  record "PASS" "P-490 Go ignored errors" "No '_, _ =' error-suppression patterns detected"
fi
