#!/bin/bash
# P-220: Data Integrity
echo "P-220: Data Integrity"
SRC="${SOURCE_DIR:-.}"

fk_constraints=$(grep -rn --include="*.sql" 'FOREIGN KEY\|REFERENCES' "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | wc -l | tr -d ' ')
if [[ $fk_constraints -gt 5 ]]; then record "PASS" "P-220 Foreign keys" "$fk_constraints FK constraints found in migrations"; else record "WARN" "P-220 Foreign keys" "Only $fk_constraints FK constraints — financial tables need referential integrity"; fi

not_null=$(grep -rn --include="*.sql" 'NOT NULL' "$SRC" 2>/dev/null | grep -i "amount\|balance\|currency\|client_id\|status" | grep -v "test\|Test\|target" | wc -l | tr -d ' ')
if [[ $not_null -gt 5 ]]; then record "PASS" "P-220 NOT NULL constraints" "$not_null NOT NULL constraints on critical columns"; else record "WARN" "P-220 NOT NULL constraints" "Few NOT NULL constraints on financial columns"; fi

reconciliation=$(grep -rn --include="$SRC_EXT" 'reconcil\|Reconcil\|balance.*check\|drift.*detect\|sum.*transaction\|SUM.*transaction' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$reconciliation" ]]; then record "PASS" "P-220 Reconciliation" "Balance reconciliation patterns found"; else record "WARN" "P-220 Reconciliation" "No reconciliation patterns — periodic balance verification recommended"; fi

dedup=$(grep -rn --include="$SRC_EXT" 'idempoten\|Idempoten\|ON CONFLICT\|duplicate.*check\|already.*processed\|dedup' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$dedup" ]]; then record "PASS" "P-220 Deduplication" "Transaction deduplication patterns found"; else record "FAIL" "P-220 Deduplication" "No deduplication — duplicate transactions create financial discrepancies"; fi

enum_check=$(grep -rn --include="*.sql" 'CHECK\|ENUM\|constraint.*status' "$SRC" 2>/dev/null | grep -i "status\|type\|state" | grep -v "test\|Test\|target" | head -3)
if [[ -n "$enum_check" ]]; then record "PASS" "P-220 Status validation" "Status/enum constraints found"; else record "WARN" "P-220 Status validation" "No CHECK constraints on status columns — invalid states can corrupt workflows"; fi

unique_idx=$(grep -rn --include="*.sql" 'UNIQUE\|unique' "$SRC" 2>/dev/null | grep -i "transaction\|payment\|order\|idempot" | grep -v "test\|Test\|target" | wc -l | tr -d ' ')
if [[ $unique_idx -gt 0 ]]; then record "PASS" "P-220 Unique constraints" "$unique_idx unique constraints on financial identifiers"; else record "WARN" "P-220 Unique constraints" "No unique constraints on transaction identifiers"; fi
