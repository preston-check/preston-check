#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-314
name: MPC / Threshold Signature Scheme Usage
description: Verifies that institutional-custody signing flows use multi-party computation (MPC) or threshold signature schemes (TSS) so no single key shard can sign a transaction unilaterally. Single-key signing — even HSM-backed — concentrates risk in one operator or one device; MPC distributes that risk across multiple parties or geographic regions.
category: code-scan
severity: medium
languages: typescript, javascript, java, python, go, rust
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NIST-CSF:2.0:PR.DS
cwe: 320
false_positive_rate: high
performance_class: fast
origin: Institutional crypto custody best practice. Major qualified custodians (Fireblocks, BitGo, Anchorage, Coinbase Prime) all rely on MPC/TSS for the trust story they sell to regulated counterparties.
PRESTON_META

echo "P-314: MPC / Threshold Signatures"

SRC="${SOURCE_DIR:-.}"

# Look for MPC/TSS library references or self-implemented schemes
mpc_refs=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" \
  -iE 'fireblocks|sepior|tss[\._-]|threshold[_-]signature|gennaro|frost.*signature|partisig|multi[_-]party[_-]computation|@safeheron|mpc[_-]wallet|coinbase.*mpc|copper.*walletconnect.*mpc' "$SRC" 2>/dev/null \
  | grep -vE '/test/|node_modules|/mock' || true)

# Detect any signing
any_sign=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -E 'signTransaction|signMessage|wallet\.sign|ecdsa.*sign|secp256k1.*sign' "$SRC" 2>/dev/null \
  | grep -vE '/test/|node_modules|/mock' || true)

if [[ -z "$any_sign" ]]; then
  record "SKIP" "P-314 MPC / TSS" "No transaction signing detected"
  return 0 2>/dev/null || true
fi

if [[ -n "$mpc_refs" ]]; then
  count=$(echo "$mpc_refs" | wc -l | tr -d ' ')
  record "PASS" "P-314 MPC / TSS" "MPC/TSS integration referenced in $count file(s)"
else
  record "WARN" "P-314 MPC / TSS" "Signing detected without MPC/TSS reference; consider for institutional custody risk reduction"
fi
