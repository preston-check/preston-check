#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-21
name: PCI-DSS Card Data
description: Checks for raw PAN in source/logs, tokenization.
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
frameworks: PCI-DSS:4.0:3.3, PCI-DSS:4.0:3.4, PCI-DSS:4.0:3.5.1, SOC2:TSC-2017:CC6.5, ISO-27001:2022:8.11, CIS-v8:3.12
PRESTON_META


# P-21: PCI-DSS Card Data Handling
# Raw PAN must never be stored, logged, or passed as query params.
echo "P-21: PCI-DSS Card Data"
SRC="${SOURCE_DIR:-.}"

pan=$(grep -rn --include="*.java" --include="*.ts" \
  "['\"][0-9]\{13,19\}['\"]" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|mock\|/db/\|Acceptor\|Identifier\|MERCHANT\|merchant_id\|static final" | head -3)
if [[ -z "$pan" ]]; then
  record "PASS" "P-21 No raw PAN" "No raw card numbers in source"
else
  record "FAIL" "P-21 No raw PAN" "Card number patterns found in source code" "$(echo "$pan" | head -10)"
fi

card_logs=$(grep -rn --include="*.java" \
  'log\..*cardNumber\|log\..*card_number\|log\..*creditCard' \
  "$SRC/credit-card-service" "$SRC/credit-card-service-logic" 2>/dev/null \
  | grep -v "test\|Test\|target\|mask\|token\|last4\|redact" | head -3)
if [[ -z "$card_logs" ]]; then
  record "PASS" "P-21 No PAN in logs" "No card data in log statements"
else
  record "FAIL" "P-21 No PAN in logs" "Card data found in log statements" "$(echo "$card_logs" | head -10)"
fi

tokenization=$(grep -rn --include="*.java" \
  "tok_\|pm_\|tokenize\|stripeToken\|paymentMethod\|payment_intent" \
  "$SRC/credit-card-service" "$SRC/credit-card-service-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$tokenization" ]]; then
  record "PASS" "P-21 Tokenization" "Payment tokenization patterns found"
else
  record "WARN" "P-21 Tokenization" "No tokenization patterns found — verify Stripe/processor handles PAN" "$(echo "$tokenization" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "[0-9]{13,19}|cardNumber|pan\s*=" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "WARN" "P-21 PCI card data exposure (Go)" "$_go_count instance(s) found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "PASS" "P-21 PCI card data exposure (Go)" "No issues found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "[0-9]{13,19}|card_number|pan_=" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "WARN" "P-21 PCI card data exposure (Rust)" "$_rs_count instance(s) found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "PASS" "P-21 PCI card data exposure (Rust)" "No issues found in Rust files"
  fi
fi
