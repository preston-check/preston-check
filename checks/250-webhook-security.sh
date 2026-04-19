#!/bin/bash
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
