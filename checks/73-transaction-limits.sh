#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-73
name: Transaction Limits
description: Detects per-transaction limits, rolling limits, atomic enforcement.
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
frameworks: PCI-DSS:4.0:7.2, SOC2:TSC-2017:CC6.1, ISO-27001:2022:5.15, NIST-CSF:2.0:PR.AC-4
PRESTON_META


# P-73: Transaction Limit Enforcement
# Per-transaction, daily rolling, monthly rolling limits must be atomic.
# Race conditions in limit checking enable limit bypass via concurrent requests.
echo "P-73: Transaction Limits"
SRC="${SOURCE_DIR:-.}"

# Check for per-transaction limits
per_tx_limit=$(grep -rn --include="*.java" --include="*.ts" \
  "max.*transaction\|transaction.*limit\|per.*tx.*limit\|single.*transaction.*max\|max.*amount\|amount.*exceed" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -5)
if [[ -n "$per_tx_limit" ]]; then
  record "PASS" "P-73 Per-tx limits" "Per-transaction limit enforcement found"
else
  record "WARN" "P-73 Per-tx limits" "No per-transaction amount limits — every tx type should have a max" "$(echo "$per_tx_limit" | head -10)"
fi

# Check for rolling period limits (24h, monthly)
rolling_limit=$(grep -rn --include="*.java" --include="*.ts" \
  "daily.*limit\|monthly.*limit\|rolling.*limit\|24.*hour.*limit\|period.*limit\|cumulative.*limit\|window.*limit" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$rolling_limit" ]]; then
  record "PASS" "P-73 Rolling limits" "Rolling period limits found"
else
  record "WARN" "P-73 Rolling limits" "No rolling period limits (daily/monthly) — essential for AML compliance" "$(echo "$rolling_limit" | head -10)"
fi

# Check for atomic limit enforcement (FOR UPDATE or advisory lock)
atomic_limit=$(grep -rn --include="*.java" --include="*.ts" \
  "FOR UPDATE\|advisory.*lock\|pg_advisory\|SELECT.*FOR.*UPDATE.*limit\|atomic.*check\|lock.*limit" \
  "$SRC" 2>/dev/null | grep -i "limit\|counter\|balance" \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$atomic_limit" ]]; then
  record "PASS" "P-73 Atomic limits" "Atomic (locked) limit enforcement found"
else
  limit_check=$(grep -rn --include="*.java" "limit" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|SQL\|LIMIT\|rateLimit" | wc -l | tr -d ' ')
  if [[ "$limit_check" -gt 5 ]]; then
    record "WARN" "P-73 Atomic limits" "Limit checks found but no FOR UPDATE/advisory lock — concurrent requests can bypass limits" "$(echo "$limit_check" | head -10)"
  else
    record "SKIP" "P-73 Atomic limits" "No significant limit enforcement patterns found"
  fi
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "max.*transaction|transaction.*limit|maxAmount|transactionLimit|daily.*limit|monthly.*limit|dailyLimit|rolling.*limit|cumulative.*limit" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-73 Transaction Limits (Go)" "Transaction limit enforcement patterns found in Go code"
  else
    record "WARN" "P-73 Transaction Limits (Go)" "No per-transaction or rolling limit enforcement found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "max.*transaction|transaction_limit|max_amount|daily.*limit|monthly.*limit|daily_limit|rolling.*limit|cumulative.*limit" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-73 Transaction Limits (Rust)" "Transaction limit enforcement patterns found in Rust code"
  else
    record "WARN" "P-73 Transaction Limits (Rust)" "No per-transaction or rolling limit enforcement found in Rust files"
  fi
fi
