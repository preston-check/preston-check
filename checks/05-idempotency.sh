#!/bin/bash
# P-05: Idempotency on state-changing operations
# Preston probed for race conditions via rapid session polling.
# All financial mutations and webhooks must be idempotent.

echo "P-05: Idempotency Guards"

SRC="${SOURCE_DIR:-.}"

# Check webhook handlers for idempotency
# Check controller AND its sibling service layer for idempotency
webhooks=$(find "$SRC" \( -name "*Webhook*Controller*.java" -o -name "*Endpoint*Controller*.java" \) -path "*/src/*" ! -path "*/test/*" ! -path "*/target/*" 2>/dev/null)
total_wh=0
idempotent_wh=0

for w in $webhooks; do
  ((total_wh++))
  dir=$(dirname "$w")
  if grep -q "idempoten\|IdempotencyKey\|ON CONFLICT\|executeIdempotent\|webhook_idempotency" "$w" 2>/dev/null; then
    ((idempotent_wh++))
  elif grep -rq "idempoten\|IdempotencyKey\|executeIdempotent\|webhook_idempotency\|WebhookMessageStore" "$dir/../" 2>/dev/null; then
    ((idempotent_wh++))
  fi
done

if [[ $total_wh -eq 0 ]]; then
  record "SKIP" "P-05 Webhook idempotency" "No webhook handlers found"
elif [[ $idempotent_wh -eq $total_wh ]]; then
  record "PASS" "P-05 Webhook idempotency" "All $total_wh webhook handlers have idempotency"
else
  unprotected=$((total_wh - idempotent_wh))
  record "FAIL" "P-05 Webhook idempotency" "$unprotected of $total_wh webhook handlers lack idempotency"
fi

# Check financial mutation methods for locking
mutations=$(grep -rln --include="*.java" \
  "WITHDRAW\|TRANSFER\|funds_out\|payVendor\|withdraw\|deposit" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|domain\|dto\|enum\|model" \
  | head -20)

locked=0
total_mut=0
for m in $mutations; do
  ((total_mut++))
  if grep -q "FOR UPDATE\|advisory_lock\|synchronized\|executeWrite\|@Transactional" "$m" 2>/dev/null; then
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
