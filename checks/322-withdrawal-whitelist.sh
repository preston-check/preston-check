#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-322
name: Withdrawal Address Whitelist Enforcement
description: Verifies that crypto withdrawal endpoints check the destination address against a customer-pre-approved whitelist before sending. Address-whitelist controls (sometimes called "named beneficiaries" or "address book") are the single most effective control against account-takeover-driven theft.
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.AC, ISO-27001:2022:A.5.16, FATF:2023:Rec.16
cwe: 284
false_positive_rate: low
performance_class: fast
origin: ATO (account takeover) drained customer funds at multiple major exchanges where withdrawal whitelists were optional or default-off.
PRESTON_META

echo "P-322: Withdrawal Address Whitelist"

SRC="${SOURCE_DIR:-.}"

# Find withdrawal endpoints
withdraw_files=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'function\s+(withdraw|sendCrypto|payout|cryptoWithdrawal|broadcastTransaction)|@PostMapping.*withdraw|@RequestMapping.*withdraw|router\.(post|put).*withdraw|app\.(post|put).*withdraw' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$withdraw_files" ]]; then
  record "SKIP" "P-322 Withdrawal whitelist" "No crypto withdrawal endpoints detected"
  return 0 2>/dev/null || true
fi

without_whitelist=0
total=0
for f in $withdraw_files; do
  ((total++))
  if ! grep -qE 'whitelist|whitelisted|allowed[_-]address|approved[_-]address|addressBook|named[_-]beneficiary|trusted[_-]address|isAddressApproved' "$f" 2>/dev/null; then
    ((without_whitelist++))
  fi
done

if [[ $without_whitelist -eq 0 ]]; then
  record "PASS" "P-322 Withdrawal whitelist" "$total withdrawal handler(s) reference an address whitelist"
else
  record "FAIL" "P-322 Withdrawal whitelist" "$without_whitelist of $total withdrawal handler(s) lack address-whitelist enforcement" "$(echo "$withdraw_files" | head -10)"
fi
