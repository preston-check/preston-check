#!/bin/bash
###############################################################################
# Mythril integration wrapper
#
# Mythril performs symbolic execution on EVM bytecode, finding deeper
# vulnerability classes than static analysis (e.g., specific transaction
# ordering attacks, complex reentrancy chains). It is slower (minutes per
# contract) so this integration is opt-in via --mythril.
#
# Install: pip install mythril
###############################################################################

CONTRACTS_DIR="${1:-.}"

if ! command -v myth >/dev/null 2>&1; then
  echo "  ⚠️  Mythril not installed; skipping. Install: pip install mythril"
  exit 0
fi

echo "  Running Mythril on Solidity contracts in $CONTRACTS_DIR..."
echo "  (This may take several minutes per contract.)"

count=0
for contract in $(find "$CONTRACTS_DIR" -name "*.sol" -not -path "*/test/*" -not -path "*/node_modules/*" 2>/dev/null | head -10); do
  ((count++))
  echo "  [$count] Analyzing $contract..."
  myth analyze "$contract" --execution-timeout 120 2>&1 | grep -E "==== |SWC ID:" | head -10
done

echo ""
echo "  Mythril completed $count contract analyses."
