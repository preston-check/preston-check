#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-56
name: Multi-Signature Approval
description: Checks dual-approval workflows, Fireblocks co-signer/TAP.
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
frameworks: PCI-DSS:4.0:8.4.1, SOC2:TSC-2017:CC6.1, ISO-27001:2022:5.17, ISO-27001:2022:8.5
PRESTON_META

# P-56: Multi-Signature & Dual Approval
# High-value operations must require multiple approvers.
echo "P-56: Multi-Signature Approval"
SRC="${SOURCE_DIR:-.}"
dual_approval=$(grep -rn --include="*.java" \
  "approval\|PENDING_BLOX_APPROVAL\|PENDING_CLIENT_APPROVAL\|dual.*sign\|multi.*sig\|co.*sign\|approver\|authorize" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -5)
if [[ -n "$dual_approval" ]]; then
  count=$(echo "$dual_approval" | wc -l)
  record "PASS" "P-56 Approval workflow" "$count dual-approval/authorization patterns found"
else
  record "WARN" "P-56 Approval workflow" "No dual-approval workflow for high-value operations"
fi

fireblocks_cosign=$(grep -rn --include="*.java" \
  "cosigner\|co_signer\|TAP\|transaction.*approval\|callback.*handler.*sign" \
  "$SRC/FireblocksCallbackHandler" "$SRC/FireblocksSecureWalletWithdraw-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$fireblocks_cosign" ]]; then
  record "PASS" "P-56 Fireblocks co-signer" "Fireblocks co-signer/TAP integration found"
else
  record "WARN" "P-56 Fireblocks co-signer" "No Fireblocks co-signer verification found"
fi
