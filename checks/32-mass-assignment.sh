#!/bin/bash
# P-32: Mass Assignment Protection — OWASP API #3/#6
echo "P-32: Mass Assignment"
SRC="${SOURCE_DIR:-.}"

direct_entity=$(grep -rn --include="*.java" --max-count=10 \
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
