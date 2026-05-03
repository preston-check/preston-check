#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-73
name: Transaction Limits
description: Transaction Limits security check (see COMPLIANCE_MAPPING.md for details).
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
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
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
  record "WARN" "P-73 Per-tx limits" "No per-transaction amount limits — every tx type should have a max"
fi

# Check for rolling period limits (24h, monthly)
rolling_limit=$(grep -rn --include="*.java" --include="*.ts" \
  "daily.*limit\|monthly.*limit\|rolling.*limit\|24.*hour.*limit\|period.*limit\|cumulative.*limit\|window.*limit" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$rolling_limit" ]]; then
  record "PASS" "P-73 Rolling limits" "Rolling period limits found"
else
  record "WARN" "P-73 Rolling limits" "No rolling period limits (daily/monthly) — essential for AML compliance"
fi

# Check for atomic limit enforcement (FOR UPDATE or advisory lock)
atomic_limit=$(grep -rn --include="*.java" --include="*.ts" \
  "FOR UPDATE\|advisory.*lock\|pg_advisory\|SELECT.*FOR.*UPDATE.*limit\|atomic.*check\|lock.*limit" \
  "$SRC" 2>/dev/null | grep -i "limit\|counter\|balance" \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$atomic_limit" ]]; then
  record "PASS" "P-73 Atomic limits" "Atomic (locked) limit enforcement found"
else
  limit_check=$(grep -rn --include="*.java" "limit" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|node_modules\|//\|/\*\|SQL\|LIMIT\|rateLimit" | wc -l | tr -d ' ')
  if [[ "$limit_check" -gt 5 ]]; then
    record "WARN" "P-73 Atomic limits" "Limit checks found but no FOR UPDATE/advisory lock — concurrent requests can bypass limits"
  else
    record "SKIP" "P-73 Atomic limits" "No significant limit enforcement patterns found"
  fi
fi
