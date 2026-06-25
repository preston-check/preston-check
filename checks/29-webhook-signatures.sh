#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-29
name: Webhook Signatures
description: Checks per-handler signature verification for payment webhooks.
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

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "hmac\.Sum|hmac\.New|hmac\.Equal|verifySignature|x-hub-signature|stripe-signature|webhookSecret" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-29 Webhook signature verification (Go)" "Webhook signature verification patterns found in Go code" "$(echo "$_go_hits" | head -5)"
  else
    record "WARN" "P-29 Webhook signature verification (Go)" "No webhook signature verification patterns found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "hmac::Mac|hmac::Hmac|ring::hmac|verify_signature|x-hub-signature|stripe-signature|webhook_secret" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-29 Webhook signature verification (Rust)" "Webhook signature verification patterns found in Rust code" "$(echo "$_rs_hits" | head -5)"
  else
    record "WARN" "P-29 Webhook signature verification (Rust)" "No webhook signature verification patterns found in Rust files"
  fi
fi
