#!/bin/bash
# P-21: PCI-DSS Card Data Handling
# Raw PAN must never be stored, logged, or passed as query params.
echo "P-21: PCI-DSS Card Data"
SRC="${SOURCE_DIR:-.}"

pan=$(grep -rn --include="*.java" --include="*.ts" --max-count=5 \
  "['\"][0-9]\{13,19\}['\"]" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|mock\|/db/\|Acceptor\|Identifier\|MERCHANT\|merchant_id\|static final" | head -3)
if [[ -z "$pan" ]]; then
  record "PASS" "P-21 No raw PAN" "No raw card numbers in source"
else
  record "FAIL" "P-21 No raw PAN" "Card number patterns found in source code"
fi

card_logs=$(grep -rn --include="*.java" --max-count=5 \
  'log\..*cardNumber\|log\..*card_number\|log\..*creditCard' \
  "$SRC/credit-card-service" "$SRC/credit-card-service-logic" 2>/dev/null \
  | grep -v "test\|Test\|target\|mask\|token\|last4\|redact" | head -3)
if [[ -z "$card_logs" ]]; then
  record "PASS" "P-21 No PAN in logs" "No card data in log statements"
else
  record "FAIL" "P-21 No PAN in logs" "Card data found in log statements"
fi

tokenization=$(grep -rn --include="*.java" --max-count=5 \
  "tok_\|pm_\|tokenize\|stripeToken\|paymentMethod\|payment_intent" \
  "$SRC/credit-card-service" "$SRC/credit-card-service-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$tokenization" ]]; then
  record "PASS" "P-21 Tokenization" "Payment tokenization patterns found"
else
  record "WARN" "P-21 Tokenization" "No tokenization patterns found — verify Stripe/processor handles PAN"
fi
