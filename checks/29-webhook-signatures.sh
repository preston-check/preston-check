#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-29
name: Webhook Signatures
description: Checks per-handler signature verification for payment webhooks.
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
frameworks: PCI-DSS:4.0:4.2.1, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.26, OWASP-API:2023:API8
PRESTON_META


# P-29: Webhook Signature Verification
# Each payment webhook handler must verify cryptographic signatures.
echo "P-29: Webhook Signatures"
SRC="${SOURCE_DIR:-.}"

webhook_dirs=("credit-card-webhook" "cybrid-webhook" "FireblocksCallbackHandler" "PaymentsEndpointCobru" "twilio-webhook-service")
for wh in "${webhook_dirs[@]}"; do
  if [[ -d "$SRC/$wh" ]]; then
    sig=$(grep -rn --include="*.java" \
      "verifySignature\|Webhook.constructEvent\|stripe.*signature\|hmac.*verify\|validateCallback\|X-Signature\|webhook.*secret" \
      "$SRC/$wh/src" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
    if [[ -n "$sig" ]]; then
      record "PASS" "P-29 $wh signature" "Webhook signature verification found"
    else
      record "WARN" "P-29 $wh signature" "No signature verification in $wh" "$(echo "$sig" | head -10)"
    fi
  fi
done
