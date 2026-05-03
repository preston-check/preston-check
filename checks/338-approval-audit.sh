#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-338
name: Outstanding Token Approval Audit
description: Verifies that wallet UI exposes outstanding ERC-20/ERC-721 approvals to the user with revocation paths. Forgotten infinite approvals to dApps that later become compromised are the proximate cause of many wallet drainings.
category: code-scan
severity: medium
languages: typescript, javascript
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.AC, OWASP-API:2023:API3
cwe: 269
false_positive_rate: medium
performance_class: fast
origin: Revoke.cash, Etherscan token approvals, and similar tools emerged because forgotten infinite approvals are a pervasive risk surface. Major drainer kits (Inferno, Pink, Angel) all exploit this pattern.
PRESTON_META

echo "P-338: Approval Audit"

SRC="${SOURCE_DIR:-.}"

approval_audit=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -iE 'getApprovals|listApprovals|approvalsList|outstandingApprovals|revoke.cash|allowance[_-]audit|approvalAudit|tokenApprovalsList' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

# Find wallet UI / dApp
wallet_ui=$(grep -rln --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
  -iE 'walletConnect|walletKit|web3Modal|WalletProvider|connectWallet' "$SRC" 2>/dev/null \
  | grep -vE 'node_modules|/test/' || true)

if [[ -z "$wallet_ui" ]]; then
  record "SKIP" "P-338 Approval audit" "No wallet UI code detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$approval_audit" ]]; then
  count=$(echo "$approval_audit" | wc -l | tr -d ' ')
  record "PASS" "P-338 Approval audit" "$count file(s) expose outstanding approvals / revocation UI"
else
  record "WARN" "P-338 Approval audit" "Wallet UI without visible approval-audit / revocation surface" "$(echo "$wallet_ui" | head -10)"
fi
