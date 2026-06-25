#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-56
name: Multi-Signature Approval
description: Checks dual-approval workflows, Fireblocks co-signer/TAP.
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
frameworks: PCI-DSS:4.0:8.4.1, SOC2:TSC-2017:CC6.1, ISO-27001:2022:5.17, ISO-27001:2022:8.5, NIST-CSF:2.0:PR.AA-3
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
  record "WARN" "P-56 Approval workflow" "No dual-approval workflow for high-value operations" "$(echo "$dual_approval" | head -10)"
fi

fireblocks_cosign=$(grep -rn --include="*.java" \
  "cosigner\|co_signer\|TAP\|transaction.*approval\|callback.*handler.*sign" \
  "$SRC/FireblocksCallbackHandler" "$SRC/FireblocksSecureWalletWithdraw-logic" 2>/dev/null \
  | grep -v "test\|Test\|target" | head -3)
if [[ -n "$fireblocks_cosign" ]]; then
  record "PASS" "P-56 Fireblocks co-signer" "Fireblocks co-signer/TAP integration found"
else
  record "WARN" "P-56 Fireblocks co-signer" "No Fireblocks co-signer verification found" "$(echo "$fireblocks_cosign" | head -10)"
fi

# --- Go ---
_go_files=$(find "$SRC" -name "*.go" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_go_files:-0} -gt 0 ]]; then
  _go_hits=$(grep -rn --include="*.go" --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules -E "approval|dual.*sign|multi.*sig|co.*sign|approver|authorize|cosigner|co_signer|transaction.*approval" "$SRC" 2>/dev/null | grep -vE "_test\.go|/vendor/" || true)
  _go_count=$([[ -n "$_go_hits" ]] && echo "$_go_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_go_count:-0} -gt 0 ]]; then
    record "PASS" "P-56 Multi-Signature Approval (Go)" "Dual-approval or multi-sig workflow patterns found in Go code"
  else
    record "WARN" "P-56 Multi-Signature Approval (Go)" "No multi-signature or dual-approval workflow found in Go files"
  fi
fi

# --- Rust ---
_rs_files=$(find "$SRC" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ ${_rs_files:-0} -gt 0 ]]; then
  _rs_hits=$(grep -rn --include="*.rs" --exclude-dir=.git --exclude-dir=target -E "approval|dual.*sign|multi.*sig|co.*sign|approver|authorize|cosigner|co_signer|transaction.*approval" "$SRC" 2>/dev/null | grep -vE "#\[cfg\(test\)|/tests?/" || true)
  _rs_count=$([[ -n "$_rs_hits" ]] && echo "$_rs_hits" | wc -l | tr -d ' ' || echo 0)
  if [[ ${_rs_count:-0} -gt 0 ]]; then
    record "PASS" "P-56 Multi-Signature Approval (Rust)" "Dual-approval or multi-sig workflow patterns found in Rust code"
  else
    record "WARN" "P-56 Multi-Signature Approval (Rust)" "No multi-signature or dual-approval workflow found in Rust files"
  fi
fi
