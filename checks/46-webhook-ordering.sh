#!/bin/bash
# P-46: Webhook Replay & Event Ordering
echo "P-46: Webhook Ordering"
SRC="${SOURCE_DIR:-.}"
event_store=$(grep -rn --include="*.java" --max-count=5 "WebhookMessageStore\|webhook_raw_messages\|saveEvent\|persistEvent\|eventLog" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$event_store" ]]; then record "PASS" "P-46 Event persistence" "Webhook event storage found"; else record "WARN" "P-46 Event persistence" "No webhook event persistence for reconciliation"; fi
dead_letter=$(grep -rn --include="*.java" --include="*.yml" --max-count=5 "deadLetter\|dead.*letter\|retry.*queue\|DLQ\|maxRetries\|retryCount" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$dead_letter" ]]; then record "PASS" "P-46 Dead letter queue" "Retry/dead-letter mechanism found"; else record "WARN" "P-46 Dead letter queue" "No dead-letter queue for failed webhooks"; fi
