#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-517
name: Move Resource Semantics and Storage Discipline
description: Detects Move modules that produce or consume resources without explicit move_to / move_from operations or proper has key/store annotations. Resource-leak-like bugs in Move can lock funds or break linear-typing guarantees.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.4.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC04, CWE:404
cwe: 404
false_positive_rate: high
performance_class: fast
origin: Move's resource model is its core security primitive; misuse causes value-locked-forever bugs (Aptos and Sui audit findings).
PRESTON_META

echo "P-517: Move Resource Semantics"

SRC="${SOURCE_DIR:-.}"
move_files=$(find "$SRC" -name "*.move" -not -path "*/build/*" 2>/dev/null)

if [[ -z "$move_files" ]]; then
  record "SKIP" "P-517 Move resources" "No Move modules detected"
  return 0 2>/dev/null || true
fi

resource_decls=$(grep -rln --include="*.move" -E "struct\s+[A-Z][A-Za-z0-9_]*\s+has\s+(key|store)" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null || true)
storage_ops=$(grep -rln --include="*.move" -E "\bmove_to\s*\(|\bmove_from\s*\(|\bborrow_global\b|\bexists\b\s*<" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null || true)

r_count=$([[ -n "$resource_decls" ]] && echo "$resource_decls" | wc -l | tr -d ' ' || echo 0)
s_count=$([[ -n "$storage_ops" ]] && echo "$storage_ops" | wc -l | tr -d ' ' || echo 0)

if [[ ${r_count:-0} -eq 0 ]]; then
  record "SKIP" "P-517 Move resources" "No resource-typed structs detected"
elif [[ ${s_count:-0} -eq 0 ]]; then
  record "WARN" "P-517 Move resources" "$r_count resource declaration(s) without observable move_to/move_from/borrow_global usage" "$(echo "$resource_decls" | head -10)"
else
  record "PASS" "P-517 Move resources" "$r_count resource(s) and $s_count storage-operation file(s); semantics tracked"
fi
