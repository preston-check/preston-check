#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-47
name: Financial Reconciliation
description: Checks external balance comparison, compensation patterns.
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
frameworks: SOC2:TSC-2017:CC4.1, ISO-27001:2022:8.34
PRESTON_META

# P-47: Financial Reconciliation Controls
echo "P-47: Financial Reconciliation"
SRC="${SOURCE_DIR:-.}"
reconciliation=$(grep -rn --include="*.java" --include="*.ts" "reconcil\|Reconcil\|balance.*check\|verifyBalance\|compareBalance\|settlement.*check" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$reconciliation" ]]; then record "PASS" "P-47 Reconciliation" "Financial reconciliation mechanism found"; else record "WARN" "P-47 Reconciliation" "No reconciliation between internal and external balances"; fi
compensation=$(grep -rn --include="*.java" "compensat\|rollback.*transaction\|saga\|undo.*step\|revert.*payment\|cancel.*transfer" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$compensation" ]]; then record "PASS" "P-47 Compensation pattern" "Transaction compensation/reversal found"; else record "WARN" "P-47 Compensation pattern" "No saga/compensation for multi-step operations"; fi
