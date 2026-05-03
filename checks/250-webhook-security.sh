#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-250
name: Webhook Security
description: Detects missing signature verification, replay protection on webhooks.
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
frameworks: PCI-DSS:4.0:6.4.1, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.26, NIST-CSF:2.0:PR.DS-2
PRESTON_META


# P-250: Webhook Security
echo "P-250: Webhook Security"
SRC="${SOURCE_DIR:-.}"

sig_verify=$(grep -rn --include="$SRC_EXT" 'verifySignature\|verify.*signature\|validateSignature\|hmac.*verify\|x-.*signature\|HMAC.*SHA\|webhook.*secret\|signing.*key' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | wc -l | tr -d ' ')
if [[ $sig_verify -gt 2 ]]; then record "PASS" "P-250 Webhook signatures" "$sig_verify signature verification patterns found"; else record "WARN" "P-250 Webhook signatures" "Few webhook signature verifications — all webhooks should verify sender identity"; fi

replay=$(grep -rn --include="$SRC_EXT" 'timestamp.*fresh\|timestamp.*valid\|replay.*protect\|nonce.*check\|too.*old\|stale.*webhook' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$replay" ]]; then record "PASS" "P-250 Replay protection" "Webhook replay protection found"; else record "WARN" "P-250 Replay protection" "No webhook replay protection — old webhooks can be replayed"; fi

webhook_idemp=$(grep -rn --include="$SRC_EXT" 'recordIncoming\|webhook.*idempoten\|event.*id.*check\|duplicate.*webhook\|WebhookMessageStore' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$webhook_idemp" ]]; then record "PASS" "P-250 Webhook idempotency" "Webhook deduplication/idempotency patterns found"; else record "FAIL" "P-250 Webhook idempotency" "No webhook deduplication — retry storms create duplicate processing"; fi

webhook_err=$(grep -rn --include="$SRC_EXT" 'webhook.*error\|callback.*error\|webhook.*fail\|markProcessed\|processing_result' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$webhook_err" ]]; then record "PASS" "P-250 Webhook error handling" "Webhook error tracking patterns found"; else record "WARN" "P-250 Webhook error handling" "No webhook error tracking — failed webhooks should be logged and retried"; fi

webhook_log=$(grep -rn --include="$SRC_EXT" 'webhook.*log\|callback.*log\|raw.*payload\|webhook_raw_messages\|recordIncoming' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$webhook_log" ]]; then record "PASS" "P-250 Webhook audit trail" "Webhook payload logging found"; else record "WARN" "P-250 Webhook audit trail" "No webhook audit trail — all payloads should be stored for forensics"; fi
