#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-320
name: Multi-Sig Approval Discipline
description: Verifies that high-value transactions and admin operations require multi-signature approval with appropriate thresholds (2-of-3, 3-of-5) rather than a single signer. Single-signer approval for high-value movements concentrates risk in one operator and is the proximate cause of many insider-threat exchange compromises.
category: code-scan
severity: high
languages: typescript, javascript, java, python, go, rust, solidity
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.AC, ISO-27001:2022:A.5.16
cwe: 269
false_positive_rate: medium
performance_class: fast
origin: Insider-driven exchange withdrawals and rogue-employee scenarios consistently bypass single-signer approval. Industry standard for institutional custody is M-of-N multi-sig.
PRESTON_META

echo "P-320: Multi-Sig Approval Discipline"

SRC="${SOURCE_DIR:-.}"

# Look for multi-sig references
multisig_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.sol" --include="*.yml" --include="*.yaml" \
  -iE 'multisig|multi[_-]sig|gnosis[_-]safe|safe\.signTransaction|approval[_-]threshold|requiredApprovals|requiredSigners|nonReentrant.*onlyOwner.*timelock|cosigner|co[_-]signer|threshold[_-]signature|twoOfThree|threeOfFive|2of3|3of5' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

# Look for high-value send paths
send_paths=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'sendCrypto|withdraw|payOut|disburseBatch|sendBatch|treasuryWithdraw|adminWithdraw|adminTransfer|emergencyWithdraw' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/|/mock' || true)

if [[ -z "$send_paths" ]]; then
  record "SKIP" "P-320 Multi-sig discipline" "No withdrawal or admin transfer code paths detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$multisig_refs" ]]; then
  count=$(echo "$multisig_refs" | wc -l | tr -d ' ')
  record "PASS" "P-320 Multi-sig discipline" "$count file(s) reference multi-sig / approval threshold patterns"
else
  record "FAIL" "P-320 Multi-sig discipline" "Withdrawal/admin transfer paths detected but no multi-sig or approval-threshold pattern found"
fi
