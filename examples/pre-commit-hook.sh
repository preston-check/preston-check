#!/bin/sh
###############################################################################
# Example: run Preston-Check's --critical-only fast-core pass as a Git
# pre-commit hook. Block the commit on any critical-severity finding.
#
# Install:
#   cp examples/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
###############################################################################

set -e

if ! command -v preston-check >/dev/null 2>&1; then
  echo "preston-check not on PATH — install via:"
  echo "  curl -fsSL https://get.preston-check.com/install.sh | sh"
  exit 1
fi

# --critical-only is the ~12-second fast-core run. Anything heavier belongs
# in CI, not a pre-commit hook.
preston-check --critical-only --airgap --ci-soft

# --ci-soft never exits 1, so we explicitly check the report. This avoids
# blocking commits when only WARNs surface, while still gating on FAILs.
if grep -q '^| FAIL ' preston-check-report.md 2>/dev/null; then
  echo ""
  echo "❌ Preston-Check found critical-severity issues. Run:"
  echo "    preston-check --critical-only"
  echo "to see details. To bypass (not recommended), use 'git commit --no-verify'."
  exit 1
fi
