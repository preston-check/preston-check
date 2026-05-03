#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-37
name: Backup & DR
description: Checks backup references, DR docs, migration rollbacks.
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
frameworks: PCI-DSS:4.0:12.10, SOC2:TSC-2017:1.2, SOC2:TSC-2017:1.3, ISO-27001:2022:8.13, ISO-27001:2022:8.14, CIS-v8:11.1
PRESTON_META

# P-37: Backup & Disaster Recovery
echo "P-37: Backup & DR"
SRC="${SOURCE_DIR:-.}"

backup=$(grep -rn --include="*.sh" --include="*.yml" --include="*.md" \
  "backup\|pg_dump\|snapshot\|restore\|recovery\|rds.*backup" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -5)
if [[ -n "$backup" ]]; then
  record "PASS" "P-37 Backup references" "Backup/recovery references found"
else
  record "WARN" "P-37 Backup references" "No backup/recovery references in codebase"
fi

dr_docs=$(find "$SRC/docs" -maxdepth 2 \( -name "*disaster*" -o -name "*DR*" -o -name "*recovery*" -o -name "*runbook*" \) 2>/dev/null | head -3)
if [[ -n "$dr_docs" ]]; then
  record "PASS" "P-37 DR documentation" "Disaster recovery documentation found"
else
  record "WARN" "P-37 DR documentation" "No disaster recovery documentation"
fi

rollback=$(grep -rn --include="*.sql" "ROLLBACK\|-- ROLLBACK\|rollback\|DOWN" \
  "$SRC/db" 2>/dev/null | head -3)
if [[ -n "$rollback" ]]; then
  record "PASS" "P-37 Migration rollback" "DB migration rollback scripts found"
else
  record "WARN" "P-37 Migration rollback" "No rollback scripts in DB migrations"
fi
