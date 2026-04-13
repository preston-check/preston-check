#!/bin/bash
# P-29: Webhook Signature Verification
# Each payment webhook handler must verify cryptographic signatures.
echo "P-29: Webhook Signatures"
SRC="${SOURCE_DIR:-.}"

webhook_dirs=("credit-card-webhook" "cybrid-webhook" "FireblocksCallbackHandler" "PaymentsEndpointCobru" "twilio-webhook-service")
for wh in "${webhook_dirs[@]}"; do
  if [[ -d "$SRC/$wh" ]]; then
    sig=$(grep -rn --include="*.java" --max-count=5 \
      "verifySignature\|Webhook.constructEvent\|stripe.*signature\|hmac.*verify\|validateCallback\|X-Signature\|webhook.*secret" \
      "$SRC/$wh/src" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
    if [[ -n "$sig" ]]; then
      record "PASS" "P-29 $wh signature" "Webhook signature verification found"
    else
      record "WARN" "P-29 $wh signature" "No signature verification in $wh"
    fi
  fi
done
