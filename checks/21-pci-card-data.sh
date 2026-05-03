#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-21
name: PCI-DSS Card Data
description: Checks for raw PAN in source/logs, tokenization.
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
  record "FAIL" "P-21 No raw PAN" "Card number patterns found in source code"
fi

card_logs=$(grep -rn --include="*.java" \
  'log\..*cardNumber\|log\..*card_number\|log\..*creditCard' \
  "$SRC/credit-card-service" "$SRC/credit-card-service-logic" 2>/dev/null \
  | grep -v "test\|Test\|target\|mask\|token\|last4\|redact" | head -3)
if [[ -z "$card_logs" ]]; then
  record "PASS" "P-21 No PAN in logs" "No card data in log statements"
else
  record "FAIL" "P-21 No PAN in logs" "Card data found in log statements"
fi

tokenization=$(grep -rn --include="*.java" \
  "tok_\|pm_\|tokenize\|stripeToken\|paymentMethod\|payment_intent" \
  "$SRC/credit-card-service" "$SRC/credit-card-service-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$tokenization" ]]; then
  record "PASS" "P-21 Tokenization" "Payment tokenization patterns found"
else
  record "WARN" "P-21 Tokenization" "No tokenization patterns found — verify Stripe/processor handles PAN"
fi
