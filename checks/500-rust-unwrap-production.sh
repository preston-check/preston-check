#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-500
name: Rust unwrap()/expect() in Production Code
description: Detects Rust unwrap() and expect() calls outside of test modules. These cause panics on Err/None, which in financial services means dropped HTTP requests, partially-applied state, or service crashes that may obscure the underlying error.
category: code-scan
severity: high
languages: rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A09, CWE:248
cwe: 248
false_positive_rate: high
performance_class: fast
origin: Rust idioms — unwrap()/expect() in production is the equivalent of unhandled exceptions in other languages; explicit error handling (?, match, or_else) is the canonical fix.
PRESTON_META

echo "P-500: Rust unwrap()/expect() in Production"

SRC="${SOURCE_DIR:-.}"
rs_count=$(find "$SRC" -name "*.rs" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rs_count" -eq 0 ]] && { record "SKIP" "P-500 Rust unwrap" "No Rust files found"; return 0 2>/dev/null || true; }

unsafe=$(grep -rn --include="*.rs" -E "\.unwrap\(\s*\)|\.expect\(" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|#\[cfg\(test\)\]|//[[:space:]]*safe:|build\.rs|/examples/" || true)
count=$([[ -n "$unsafe" ]] && echo "$unsafe" | wc -l | tr -d ' ' || echo 0)
sample=$([[ -n "$unsafe" ]] && echo "$unsafe" | head -10 || echo "")
if [[ ${count:-0} -gt 50 ]]; then
  record "FAIL" "P-500 Rust unwrap" "$count unwrap()/expect() call(s) in non-test Rust code" "$sample"
elif [[ ${count:-0} -gt 0 ]]; then
  record "WARN" "P-500 Rust unwrap" "$count unwrap()/expect() call(s); review for production paths" "$sample"
else
  record "PASS" "P-500 Rust unwrap" "No unwrap/expect detected outside tests"
fi
