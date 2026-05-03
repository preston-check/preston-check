#!/bin/bash
###############################################################################
# Slither integration wrapper
#
# Slither is the de facto static analyzer for Solidity. This wrapper runs it
# alongside Preston-Check's catalog checks and merges findings into a unified
# audit report. Slither catches a different (and complementary) class of
# bugs than grep-based checks: dataflow-aware reentrancy, uninitialized
# state variables, shadowing, divergent compiler-version behavior.
#
# Install: pip install slither-analyzer
###############################################################################

CONTRACTS_DIR="${1:-.}"

if ! command -v slither >/dev/null 2>&1; then
  echo "  ⚠️  Slither not installed; skipping. Install: pip install slither-analyzer"
  exit 0
fi

echo "  Running Slither on $CONTRACTS_DIR..."
slither "$CONTRACTS_DIR" --json /tmp/slither-output.json 2>/dev/null || true

if [[ -f /tmp/slither-output.json ]] && command -v jq >/dev/null; then
  total=$(jq '.results.detectors | length' /tmp/slither-output.json 2>/dev/null)
  high=$(jq '[.results.detectors[] | select(.impact=="High")] | length' /tmp/slither-output.json 2>/dev/null)
  med=$(jq '[.results.detectors[] | select(.impact=="Medium")] | length' /tmp/slither-output.json 2>/dev/null)
  low=$(jq '[.results.detectors[] | select(.impact=="Low")] | length' /tmp/slither-output.json 2>/dev/null)
  echo "  Slither: ${total:-0} findings (${high:-0} High, ${med:-0} Medium, ${low:-0} Low)"
  if [[ "${high:-0}" -gt 0 ]]; then
    echo "  Top high-impact findings:"
    jq -r '.results.detectors[] | select(.impact=="High") | "    [" + .check + "] " + .description' /tmp/slither-output.json 2>/dev/null | head -5
  fi
else
  echo "  Slither output not available."
fi
