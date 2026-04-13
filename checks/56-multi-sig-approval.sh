#!/bin/bash
# P-56: Multi-Signature & Dual Approval
# High-value operations must require multiple approvers.
echo "P-56: Multi-Signature Approval"
SRC="${SOURCE_DIR:-.}"
dual_approval=$(grep -rn --include="*.java" --max-count=5 \
  "approval\|PENDING_BLOX_APPROVAL\|PENDING_CLIENT_APPROVAL\|dual.*sign\|multi.*sig\|co.*sign\|approver\|authorize" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -5)
if [[ -n "$dual_approval" ]]; then
  count=$(echo "$dual_approval" | wc -l)
  record "PASS" "P-56 Approval workflow" "$count dual-approval/authorization patterns found"
else
  record "WARN" "P-56 Approval workflow" "No dual-approval workflow for high-value operations"
fi

fireblocks_cosign=$(grep -rn --include="*.java" --max-count=5 \
  "cosigner\|co_signer\|TAP\|transaction.*approval\|callback.*handler.*sign" \
  "$SRC/FireblocksCallbackHandler" "$SRC/FireblocksSecureWalletWithdraw-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$fireblocks_cosign" ]]; then
  record "PASS" "P-56 Fireblocks co-signer" "Fireblocks co-signer/TAP integration found"
else
  record "WARN" "P-56 Fireblocks co-signer" "No Fireblocks co-signer verification found"
fi
