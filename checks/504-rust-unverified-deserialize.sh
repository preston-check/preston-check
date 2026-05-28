#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-504
name: Rust Unverified serde Deserialization
description: Detects Rust serde deserialization of untrusted input without size limits, depth limits, or schema validation. Untrusted deserialization is a recurring CVE class (zip-slip-style attacks, billion-laughs DoS).
category: code-scan
severity: medium
languages: rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-Top-10:2021:A08, CWE:502
cwe: 502
false_positive_rate: high
performance_class: fast
origin: Rust serde ecosystem patterns; Rust safety doesn't extend to deserialization-induced resource exhaustion.
PRESTON_META

echo "P-504: Rust Unverified Deserialization"

SRC="${SOURCE_DIR:-.}"
rs_count=$(find "$SRC" -name "*.rs" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rs_count" -eq 0 ]] && { record "SKIP" "P-504 Rust deserialization" "No Rust files found"; return 0 2>/dev/null || true; }

deser=$(grep -rln --include="*.rs" -E "from_str|from_slice|from_reader|serde_json::from_" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -vE "/tests?/" || true)
limits=$(grep -rln --include="*.rs" -iE "max_size|max_length|depth_limit|byte_limit|tonic.*max_recv|axum.*content_length|RequestBodyLimit" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -vE "/tests?/" || true)
d_count=$([[ -n "$deser" ]] && echo "$deser" | wc -l | tr -d ' ' || echo 0)
l_count=$([[ -n "$limits" ]] && echo "$limits" | wc -l | tr -d ' ' || echo 0)
if [[ ${d_count:-0} -eq 0 ]]; then
  record "SKIP" "P-504 Rust deserialization" "No serde deserialization detected"
elif [[ ${l_count:-0} -gt 0 ]]; then
  record "PASS" "P-504 Rust deserialization" "$d_count deserialization site(s); $l_count file(s) reference size/depth limits"
else
  record "WARN" "P-504 Rust deserialization" "$d_count deserialization site(s) without observable size/depth limits" "$(echo "$limits" | head -10)"
fi
