#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-501
name: Rust Integer Overflow Without checked_*/saturating_*
description: Detects Rust arithmetic on integer types holding financial values without explicit checked_*, saturating_*, or wrapping_* methods. Release builds wrap silently on overflow; debug builds panic. Either is wrong for money — checked_add and explicit error handling is the safe path.
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
frameworks: OWASP-Top-10:2021:A04, CWE:190
cwe: 190
false_positive_rate: medium
performance_class: fast
origin: Rust release-mode integer overflow defaults to wrap; financial code must use checked_add/checked_sub/checked_mul.
PRESTON_META

echo "P-501: Rust Integer Overflow"

SRC="${SOURCE_DIR:-.}"
rs_count=$(find "$SRC" -name "*.rs" 2>/dev/null | wc -l | tr -d ' ')
[[ "$rs_count" -eq 0 ]] && { record "SKIP" "P-501 Rust integer overflow" "No Rust files found"; return 0 2>/dev/null || true; }

money_arith=$(grep -rn --include="*.rs" -E "(amount|balance|fee|price|cost)\s*[-+*]\s*" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/|#\[cfg\(test\)\]|checked_|saturating_|wrapping_|/examples/" | head -20 || true)
checked=$(grep -rln --include="*.rs" -E "checked_(add|sub|mul|div)|saturating_(add|sub|mul)" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/tests?/" || true)
m_count=$([[ -n "$money_arith" ]] && echo "$money_arith" | wc -l | tr -d ' ' || echo 0)
c_count=$([[ -n "$checked" ]] && echo "$checked" | wc -l | tr -d ' ' || echo 0)
if [[ ${m_count:-0} -gt 0 && ${c_count:-0} -eq 0 ]]; then
  record "WARN" "P-501 Rust integer overflow" "$m_count money-arithmetic line(s) without checked_/saturating_ usage anywhere" "$(echo "$checked" | head -10)"
elif [[ ${c_count:-0} -gt 0 ]]; then
  record "PASS" "P-501 Rust integer overflow" "$c_count file(s) use checked_/saturating_ arithmetic"
else
  record "PASS" "P-501 Rust integer overflow" "No money-arithmetic patterns detected"
fi
