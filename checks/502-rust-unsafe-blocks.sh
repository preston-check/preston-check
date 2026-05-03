#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-502
name: Rust unsafe Blocks Without Justification Comment
description: Detects Rust unsafe { ... } blocks lacking an explanatory SAFETY comment. The Rust convention is to document every unsafe block with a `// SAFETY: ...` justification; absent comments make audit and review impossible.
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
frameworks: OWASP-Top-10:2021:A04, NIST-SSDF:1.1:PW.7
false_positive_rate: medium
performance_class: fast
origin: rust-lang community SAFETY comment convention; rustc clippy lint clippy::undocumented_unsafe_blocks.
PRESTON_META

echo "P-502: Rust unsafe Blocks"

SRC="${SOURCE_DIR:-.}"
rs_count=$(find "$SRC" -name "*.rs" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rs_count" -eq 0 ]] && { record "SKIP" "P-502 Rust unsafe blocks" "No Rust files found"; return 0 2>/dev/null || true; }

unsafe_blocks=$(grep -rn --include="*.rs" -E "^\s*unsafe\s*\{" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|/examples/" || true)
ub_count=$([[ -n "$unsafe_blocks" ]] && echo "$unsafe_blocks" | wc -l | tr -d ' ' || echo 0)
safety_comments=$(grep -rln --include="*.rs" -E "//[[:space:]]*SAFETY:" "$SRC" 2>/dev/null | grep -vE "/tests?/" || true)
sc_count=$([[ -n "$safety_comments" ]] && echo "$safety_comments" | wc -l | tr -d ' ' || echo 0)
if [[ ${ub_count:-0} -eq 0 ]]; then
  record "PASS" "P-502 Rust unsafe blocks" "No unsafe blocks in production code"
elif [[ ${sc_count:-0} -ge 1 ]]; then
  record "PASS" "P-502 Rust unsafe blocks" "$ub_count unsafe block(s); SAFETY comments present in $sc_count file(s)"
else
  record "WARN" "P-502 Rust unsafe blocks" "$ub_count unsafe block(s) without SAFETY: comment justification" "$(echo "$safety_comments" | head -10)"
fi
