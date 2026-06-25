#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-32
name: Mass Assignment
description: Checks raw entities as @Body, missing DTO pattern.
category: code-scan
severity: medium
languages: any, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.1.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.2.4, ISO-27001:2022:8.26, OWASP-API:2023:API3
PRESTON_META


# P-32: Mass Assignment Protection — OWASP API #3/#6
echo "P-32: Mass Assignment"
SRC="${SOURCE_DIR:-.}"

direct_entity=$(grep -rn --include="*.java" \
  "@Body.*Client\b\|@Body.*User\b\|@Body.*Portfolio\b" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|Dto\|DTO\|Request\|Command\|View" | head -5)
if [[ -z "$direct_entity" ]]; then
  record "PASS" "P-32 No raw entities as @Body" "Request bodies use DTOs, not raw entities"
else
  count=$(echo "$direct_entity" | wc -l)
  record "WARN" "P-32 Raw entities as @Body" "$count endpoints accept raw entities (risk: role/balance override)" "$(echo "$direct_entity" | head -10)"
fi

dto_count=$(find "$SRC" -name "*Dto.java" -o -name "*DTO.java" -o -name "*Request.java" -o -name "*Command.java" \
  2>/dev/null | grep -v "test\|Test\|target" | wc -l)
if [[ $dto_count -gt 5 ]]; then
  record "PASS" "P-32 DTO pattern" "$dto_count DTO/Request classes found"
else
  record "WARN" "P-32 DTO pattern" "Only $dto_count DTO classes — consider adding more" "$(echo "$dto_count" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "json\.NewDecoder|json\.Unmarshal" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-32 Mass assignment risk (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-32 Mass assignment risk (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "serde::Deserialize|from_str.*Deserialize|deserialize\(" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-32 Mass assignment risk (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-32 Mass assignment risk (Rust)" "No issues found in Rust files"
  fi
fi
