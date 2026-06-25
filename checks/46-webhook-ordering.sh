#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-46
name: Webhook Ordering
description: Checks event persistence, dead-letter queues.
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
frameworks: SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:PR.DS-6
PRESTON_META


# P-46: Webhook Replay & Event Ordering
echo "P-46: Webhook Ordering"
SRC="${SOURCE_DIR:-.}"
event_store=$(grep -rn --include="*.java" "WebhookMessageStore\|webhook_raw_messages\|saveEvent\|persistEvent\|eventLog" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$event_store" ]]; then record "PASS" "P-46 Event persistence" "Webhook event storage found"; else record "WARN" "P-46 Event persistence" "No webhook event persistence for reconciliation"; fi
dead_letter=$(grep -rn --include="*.java" --include="*.yml" "deadLetter\|dead.*letter\|retry.*queue\|DLQ\|maxRetries\|retryCount" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$dead_letter" ]]; then record "PASS" "P-46 Dead letter queue" "Retry/dead-letter mechanism found"; else record "WARN" "P-46 Dead letter queue" "No dead-letter queue for failed webhooks"; fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "saveEvent|persistEvent|eventLog|WebhookStore|deadLetter|dead.*letter|retry.*queue|DLQ|maxRetries|retryCount" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-46 Webhook Event Ordering (Go)" "Webhook event persistence/DLQ found in Go code"
  else
    record "WARN" "P-46 Webhook Event Ordering (Go)" "No webhook event persistence or dead-letter queue found in Go code"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "save_event|persist_event|event_log|webhook_store|dead_letter|retry_queue|DLQ|max_retries|retry_count" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-46 Webhook Event Ordering (Rust)" "Webhook event persistence/DLQ found in Rust code"
  else
    record "WARN" "P-46 Webhook Event Ordering (Rust)" "No webhook event persistence or dead-letter queue found in Rust code"
  fi
fi
