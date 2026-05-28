#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-492
name: Go Race Conditions on Shared State
description: Detects Go goroutines that mutate shared struct fields without sync.Mutex, sync.RWMutex, or atomic operations. Common bug class in concurrent fintech services causing balance drift, double-spend, and order reordering.
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
frameworks: OWASP-Top-10:2021:A04, CWE:362
cwe: 362
false_positive_rate: high
performance_class: fast
origin: Go race detector and 'go test -race' catch many but not all; static checks complement runtime detection.
PRESTON_META

echo "P-492: Go Race Conditions"

SRC="${SOURCE_DIR:-.}"
go_count=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$go_count" -eq 0 ]] && { record "SKIP" "P-492 Go races" "No Go files found"; return 0 2>/dev/null || true; }

goroutines=$(grep -rln --include="*.go" -E "go\s+func\s*\(|go\s+[a-zA-Z][a-zA-Z0-9_]*\." --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -vE "/vendor/|_test\.go" || true)
[[ -z "$goroutines" ]] && { record "SKIP" "P-492 Go races" "No goroutines detected"; return 0 2>/dev/null || true; }

mutex_use=$(grep -rln --include="*.go" -E "sync\.Mutex|sync\.RWMutex|sync/atomic|atomic\." --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -vE "/vendor/|_test\.go" || true)
gor_count=$(echo "$goroutines" | wc -l | tr -d ' ')
mu_count=$([[ -n "$mutex_use" ]] && echo "$mutex_use" | wc -l | tr -d ' ' || echo 0)

if [[ ${mu_count:-0} -gt 0 ]]; then
  record "PASS" "P-492 Go races" "$gor_count file(s) use goroutines; $mu_count file(s) use mutex/atomic"
else
  record "WARN" "P-492 Go races" "$gor_count file(s) use goroutines without observable sync primitives" "$(echo "$mutex_use" | head -10)"
fi
