#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-712
name: Refund / Claim Authorization Missing
description: Detects refund() and similar value-returning functions in HTLC / escrow contracts that lack an explicit msg.sender check against the stored sender (or recipient for claim). Without authorization, anyone can trigger a refund — funds still go to the original sender, but an attacker can grief by forcing refunds before the legitimate counterparty claims, breaking the atomic-swap guarantee.
category: code-scan
severity: critical
languages: solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.7.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-SC-Top-10:2025:SC02, CWE:284
cwe: 284
false_positive_rate: medium
performance_class: fast
origin: digital_escrow HTLC SC-C1 (Jan 2026) — refund() was callable by anyone. Fix added `if (msg.sender != htlc.sender) revert UnauthorizedRefund();` and an explicit error type. The same class applies to any state-machine transition keyed on stored addresses.
PRESTON_META

echo "P-712: Refund / Claim Authorization Missing"

SRC="${SOURCE_DIR:-.}"
htlc_files=$(grep -rl --include="*.sol" -E '\b(HTLC|atomic\s*swap|hashLock|preimage|escrow.*refund)\b' "$SRC" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$htlc_files" ]]; then
  record "SKIP" "P-712 Refund authorization" "No HTLC / refund-bearing contracts detected"
  return 0 2>/dev/null || true
fi

bad=""
for f in $htlc_files; do
  # Locate refund function bodies via awk, then check each body for sender authorization.
  result=$(awk '
    /function\s+(refund|claim|withdraw)[A-Za-z_0-9]*\s*\(/ {
      depth = 0; in_fn = 1; body = ""; sig = $0;
    }
    in_fn {
      body = body "\n" $0;
      for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1);
        if (c == "{") depth++;
        else if (c == "}") {
          depth--;
          if (depth == 0) {
            print sig;
            print body;
            print "===END===";
            in_fn = 0; body = ""; break;
          }
        }
      }
    }
  ' "$f" 2>/dev/null)

  # Split into bodies and check each
  current=""
  while IFS= read -r line; do
    if [[ "$line" == "===END===" ]]; then
      # Body collected. Check if it contains msg.sender check OR onlyOwner-like modifier.
      has_auth=$(echo "$current" | grep -cE 'msg\.sender\s*(==|!=)|onlyOwner|onlyHandler|onlySender|onlyRecipient|require\s*\(\s*msg\.sender' 2>/dev/null)
      if [[ ${has_auth:-0} -eq 0 ]]; then
        sig=$(echo "$current" | head -1 | sed 's/^[[:space:]]*//')
        bad="${bad}${f}: ${sig}"$'\n'
      fi
      current=""
    else
      current="${current}"$'\n'"${line}"
    fi
  done <<< "$result"
done
bad=$(echo "$bad" | sed '/^$/d')

h=$(echo "$htlc_files" | wc -l | tr -d ' ')
b=$([[ -n "$bad" ]] && echo "$bad" | wc -l | tr -d ' ' || echo 0)

if [[ ${b:-0} -eq 0 ]]; then
  record "PASS" "P-712 Refund authorization" "$h HTLC/escrow file(s); refund/claim functions enforce msg.sender"
else
  record "FAIL" "P-712 Refund authorization" "$b refund/claim function(s) lack msg.sender authorization" "$bad"
fi
