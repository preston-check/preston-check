#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-46
name: Webhook Ordering
description: Checks event persistence, dead-letter queues.
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
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25
PRESTON_META

# P-46: Webhook Replay & Event Ordering
echo "P-46: Webhook Ordering"
SRC="${SOURCE_DIR:-.}"
event_store=$(grep -rn --include="*.java" "WebhookMessageStore\|webhook_raw_messages\|saveEvent\|persistEvent\|eventLog" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$event_store" ]]; then record "PASS" "P-46 Event persistence" "Webhook event storage found"; else record "WARN" "P-46 Event persistence" "No webhook event persistence for reconciliation"; fi
dead_letter=$(grep -rn --include="*.java" --include="*.yml" "deadLetter\|dead.*letter\|retry.*queue\|DLQ\|maxRetries\|retryCount" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$dead_letter" ]]; then record "PASS" "P-46 Dead letter queue" "Retry/dead-letter mechanism found"; else record "WARN" "P-46 Dead letter queue" "No dead-letter queue for failed webhooks"; fi
