#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-32
name: Mass Assignment
description: Checks raw entities as @Body, missing DTO pattern.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
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
  record "WARN" "P-32 Raw entities as @Body" "$count endpoints accept raw entities (risk: role/balance override)"
fi

dto_count=$(find "$SRC" -name "*Dto.java" -o -name "*DTO.java" -o -name "*Request.java" -o -name "*Command.java" \
  2>/dev/null | grep -v "test\|Test\|target" | wc -l)
if [[ $dto_count -gt 5 ]]; then
  record "PASS" "P-32 DTO pattern" "$dto_count DTO/Request classes found"
else
  record "WARN" "P-32 DTO pattern" "Only $dto_count DTO classes — consider adding more"
fi
