#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-47
name: Financial Reconciliation
description: Checks external balance comparison, compensation patterns.
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
frameworks: SOC2:TSC-2017:CC4.1, ISO-27001:2022:8.34, NIST-CSF:2.0:PR.DS-6
PRESTON_META


# P-47: Financial Reconciliation Controls
echo "P-47: Financial Reconciliation"
SRC="${SOURCE_DIR:-.}"
reconciliation=$(grep -rn --include="*.java" --include="*.ts" "reconcil\|Reconcil\|balance.*check\|verifyBalance\|compareBalance\|settlement.*check" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$reconciliation" ]]; then record "PASS" "P-47 Reconciliation" "Financial reconciliation mechanism found"; else record "WARN" "P-47 Reconciliation" "No reconciliation between internal and external balances"; fi
compensation=$(grep -rn --include="*.java" "compensat\|rollback.*transaction\|saga\|undo.*step\|revert.*payment\|cancel.*transfer" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$compensation" ]]; then record "PASS" "P-47 Compensation pattern" "Transaction compensation/reversal found"; else record "WARN" "P-47 Compensation pattern" "No saga/compensation for multi-step operations"; fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "reconcil|Reconcil|balance.*check|verifyBalance|compareBalance|settlement.*check|compensat|rollback.*transaction|saga|undo.*step|revert.*payment" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-47 Financial Reconciliation (Go)" "Reconciliation/compensation patterns found in Go code"
  else
    record "WARN" "P-47 Financial Reconciliation (Go)" "No reconciliation or compensation patterns found in Go code"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "reconcil|balance_check|verify_balance|compare_balance|settlement_check|compensat|rollback_transaction|saga|undo_step|revert_payment" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-47 Financial Reconciliation (Rust)" "Reconciliation/compensation patterns found in Rust code"
  else
    record "WARN" "P-47 Financial Reconciliation (Rust)" "No reconciliation or compensation patterns found in Rust code"
  fi
fi
