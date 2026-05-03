#!/bin/bash
###############################################################################
# tools/integrations/secureframe/push-evidence.sh
#
# Pushes a Preston-Check report into Secureframe as evidence-of-control.
# Secureframe's API accepts evidence uploads tagged against specific
# controls; this script reads a Preston-Check report and posts a single
# evidence record with the report attached.
#
# Required env:
#   SECUREFRAME_API_KEY — generated in Secureframe → Integrations → API
#
# Usage:
#   tools/integrations/secureframe/push-evidence.sh <preston-check-report.md>
###############################################################################

set -uo pipefail

REPORT="${1:?usage: $0 <preston-check-report.md>}"
[[ -f "$REPORT" ]] || { echo "report not found: $REPORT" >&2; exit 1; }
[[ -n "${SECUREFRAME_API_KEY:-}" ]] || { echo "SECUREFRAME_API_KEY required" >&2; exit 1; }

API="https://api.secureframe.com/v1"

# Compute summary metrics
score=$(grep "^| Score |" "$REPORT" | head -1 | awk -F'|' '{print $3}' | xargs | sed 's/%//')
fail_count=$(grep "^| FAIL |" "$REPORT" | head -1 | awk -F'|' '{print $3}' | xargs)
warn_count=$(grep "^| WARN |" "$REPORT" | head -1 | awk -F'|' '{print $3}' | xargs)

echo "Pushing Preston-Check evidence to Secureframe..."
echo "  Score: ${score}% / Fail: ${fail_count} / Warn: ${warn_count}"

report_b64=$(base64 < "$REPORT" | tr -d '\n')

curl -s -X POST "$API/evidence" \
  -H "Authorization: Bearer $SECUREFRAME_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg name "Preston-Check $(date -u +%Y-%m-%d)" \
              --arg desc "Pre-deployment security audit covering the Preston-Check 33-framework catalog" \
              --arg report "$report_b64" \
              --argjson score "${score:-0}" '{
    name: $name,
    description: $desc,
    file: {
      name: "preston-check-report.md",
      contentType: "text/markdown",
      base64: $report
    },
    metadata: {
      tool: "preston-check",
      score_percent: $score,
      automated: true
    }
  }')" >/dev/null 2>&1 && echo "    OK" || echo "    FAILED"

echo ""
echo "Secureframe push complete. Verify in Secureframe → Evidence."
