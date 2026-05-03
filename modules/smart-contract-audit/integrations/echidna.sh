#!/bin/bash
###############################################################################
# Echidna integration wrapper
#
# Echidna is a property-based fuzzer for Ethereum smart contracts. It is
# the deepest tool in this module — useful for protocols that have
# established invariants (e.g., "the sum of user balances always equals
# the total supply"). Echidna runs hundreds of thousands of fuzzed
# transactions trying to violate the invariant.
#
# Echidna requires the user to write invariants in `echidna_*` functions
# inside the contracts. This wrapper looks for those and runs Echidna
# only if they exist.
#
# Install: nix-env -i echidna  (or build from https://github.com/crytic/echidna)
###############################################################################

CONTRACTS_DIR="${1:-.}"

if ! command -v echidna >/dev/null 2>&1 && ! command -v echidna-test >/dev/null 2>&1; then
  echo "  ⚠️  Echidna not installed; skipping. Install: brew install crytic/tap/echidna"
  exit 0
fi

ECHIDNA_BIN=$(command -v echidna 2>/dev/null || command -v echidna-test 2>/dev/null)

# Find contracts with echidna_* properties defined
contracts_with_invariants=$(grep -rln --include="*.sol" -E 'function\s+echidna_[a-zA-Z]+\s*\(' "$CONTRACTS_DIR" 2>/dev/null \
  | grep -vE '/test/|/mock|node_modules' || true)

if [[ -z "$contracts_with_invariants" ]]; then
  echo "  No contracts with echidna_* invariant functions detected."
  echo "  To use Echidna, add property functions to your contracts:"
  echo "    function echidna_balances_sum() public view returns (bool) {"
  echo "      return totalSupply() == sumOfBalances();"
  echo "    }"
  exit 0
fi

echo "  Found $(echo "$contracts_with_invariants" | wc -l | tr -d ' ') contract(s) with Echidna invariants. Running fuzzer..."

for contract in $contracts_with_invariants; do
  echo "  Fuzzing $contract..."
  $ECHIDNA_BIN "$contract" --test-limit 50000 --timeout 600 2>&1 | tail -10
done
