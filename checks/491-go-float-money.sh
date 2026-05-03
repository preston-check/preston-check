#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-491
name: Go float64 for Money (Anti-Pattern)
description: Detects Go code declaring monetary fields/variables as float64 or float32. Floating-point representation cannot exactly represent decimal cents and silently corrupts cumulative balances. Use shopspring/decimal, math/big.Rat, or fixed-point integer cents instead.
category: code-scan
severity: critical
languages: go
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.2.4, NIST-CSF:2.0:PR.DS-6, OWASP-Top-10:2021:A04
cwe: 681
false_positive_rate: low
performance_class: fast
origin: Recurring fintech bug: float64 for money causes ledger drift over time. Fixed by Go ecosystem maturity (shopspring/decimal) but still appears in new code.
PRESTON_META

echo "P-491: Go float64 for Money"

SRC="${SOURCE_DIR:-.}"
go_count=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$go_count" -eq 0 ]] && { record "SKIP" "P-491 Go float money" "No Go files found"; return 0 2>/dev/null || true; }

bad=$(grep -rn --include="*.go" -E "(amount|balance|price|fee|cost|total|subtotal)\s+float(64|32)" "$SRC" 2>/dev/null \
  | grep -vE "/vendor/|_test\.go|/test/" || true)
good=$(grep -rln --include="*.go" -iE "shopspring/decimal|decimal\.Decimal|math/big\.Rat|big\.NewRat" "$SRC" 2>/dev/null \
  | grep -vE "/vendor/|_test\.go|/test/" || true)
bad_count=$([[ -n "$bad" ]] && echo "$bad" | wc -l | tr -d ' ' || echo 0)
good_count=$([[ -n "$good" ]] && echo "$good" | wc -l | tr -d ' ' || echo 0)
if [[ ${bad_count:-0} -gt 0 ]]; then
  record "FAIL" "P-491 Go float money" "$bad_count float64/float32 declaration(s) with money-keyword names"
else
  record "PASS" "P-491 Go float money" "No float-typed money fields; $good_count decimal-library reference(s)"
fi
