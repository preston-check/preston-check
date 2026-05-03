#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-05
name: Idempotency
description: Checks webhook handlers and financial operations for replay protection.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:10.2.1, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, OWASP-API:2023:API8, NIST-CSF:2.0:PR.DS-6, CIS-v8:10.5
PRESTON_META


# P-05: Idempotency on state-changing operations
# Preston probed for race conditions via rapid session polling.
# All financial mutations and webhooks must be idempotent.

echo "P-05: Idempotency Guards"

SRC="${SOURCE_DIR:-.}"

# Check webhook handlers for idempotency (language-aware)
if [[ "$DETECTED_LANG" == "go" ]]; then
  webhooks=$(find "$SRC" -name "*.go" \( -name "*webhook*" -o -name "*handler*" \) 2>/dev/null \
    | grep -iv "test\|vendor\|_test\.go" \
    | xargs grep -l -i "webhook\|HandleCallback" 2>/dev/null | head -10)
else
  webhooks=$(find "$SRC" \( -name "*Webhook*Controller*.java" -o -name "*Endpoint*Controller*.java" \) -path "*/src/*" ! -path "*/test/*" ! -path "*/target/*" 2>/dev/null)
fi

total_wh=0
idempotent_wh=0

for w in $webhooks; do
  # Skip webhook subscription management controllers (CRUD for managing webhook URLs, not inbound receivers)
  if grep -q "WebhookSubscription\|subscribe.*url\|unsubscribe\|listSubscriptions" "$w" 2>/dev/null; then
    if ! grep -q "@Post.*receive\|@Put.*receive\|@Post.*callback\|@Post.*notify\|recordIncoming\|WebhookMessageStore" "$w" 2>/dev/null; then
      continue
    fi
  fi
  ((total_wh++))
  dir=$(dirname "$w")
  if grep -q "idempoten\|IdempotencyKey\|ON CONFLICT\|Idempotency\|webhook_idempotency\|WebhookMessageStore\|recordIncoming\|FinancialOperationGuard" "$w" 2>/dev/null; then
    ((idempotent_wh++))
  elif grep -rq --include="*.java" --include="*.ts" "idempoten\|IdempotencyKey\|Idempotency\|webhook_idempotency\|WebhookMessageStore\|recordIncoming" "$dir/" 2>/dev/null; then
    ((idempotent_wh++))
  fi
done

if [[ $total_wh -eq 0 ]]; then
  # Also check for idempotency middleware
  idem_middleware=$(grep -rn --include="$SRC_EXT" "idempoten\|IdempotencyMiddleware\|IdempotencyStore" "$SRC" 2>/dev/null \
    | grep -v "test\|Test\|target\|vendor\|_test\.go" | head -3)
  if [[ -n "$idem_middleware" ]]; then
    record "PASS" "P-05 Webhook idempotency" "Idempotency middleware/store found"
  else
    record "SKIP" "P-05 Webhook idempotency" "No webhook handlers found"
  fi
elif [[ $idempotent_wh -eq $total_wh ]]; then
  record "PASS" "P-05 Webhook idempotency" "All $total_wh webhook handlers have idempotency"
else
  unprotected=$((total_wh - idempotent_wh))
  record "FAIL" "P-05 Webhook idempotency" "$unprotected of $total_wh webhook handlers lack idempotency"
fi

# Check financial mutation methods for locking
mutations=$(grep -rln --include="$SRC_EXT" \
  "$FINANCIAL_MUTATION_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|vendor\|_test\.go\|domain\|dto\|enum\|model" \
  | head -20)

locked=0
total_mut=0
for m in $mutations; do
  ((total_mut++))
  if grep -q "$FOR_UPDATE_PATTERN" "$m" 2>/dev/null; then
    ((locked++))
  fi
done

if [[ $total_mut -eq 0 ]]; then
  record "SKIP" "P-05 Financial locking" "No financial mutation files found"
elif [[ $locked -ge $((total_mut / 2)) ]]; then
  record "PASS" "P-05 Financial locking" "$locked of $total_mut financial files use locking"
else
  record "WARN" "P-05 Financial locking" "Only $locked of $total_mut financial files use locking"
fi
