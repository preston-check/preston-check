#!/bin/bash
###############################################################################
# tools/integrations/vanta/push-evidence.sh
#
# Pushes a Preston-Check report into Vanta as evidence-of-control via the
# Vanta API. Vanta's "Custom Tests" framework lets external scanners post
# pass/fail results that count toward control attestation.
#
# Required env:
#   VANTA_API_TOKEN — Vanta API token from Settings → API Tokens
#
# Usage:
#   tools/integrations/vanta/push-evidence.sh <preston-check-report.md>
###############################################################################

set -uo pipefail

REPORT="${1:?usage: $0 <preston-check-report.md>}"
[[ -f "$REPORT" ]] || { echo "report not found: $REPORT" >&2; exit 1; }
[[ -n "${VANTA_API_TOKEN:-}" ]] || { echo "VANTA_API_TOKEN required" >&2; exit 1; }

API="https://api.vanta.com/v1"

# Vanta tracks tests by external_id. Same external_id across runs updates
# the test result; new external_ids create new tests.
EXTERNAL_ID_PREFIX="preston-check"

# Compute the score and FAIL count from the report
score=$(grep "^| Score |" "$REPORT" | head -1 | awk -F'|' '{print $3}' | xargs | sed 's/%//')
fail_count=$(grep "^| FAIL |" "$REPORT" | head -1 | awk -F'|' '{print $3}' | xargs)
total=$(grep "^| Total Tests |" "$REPORT" | head -1 | awk -F'|' '{print $3}' | xargs)

result="passing"
[[ "${fail_count:-0}" -gt 0 ]] && result="failing"

echo "Pushing aggregated Preston-Check result to Vanta..."
echo "  Score: ${score}% / Fail count: ${fail_count} / Total: ${total} / Result: $result"

curl -s -X POST "$API/tests/results" \
  -H "Authorization: Bearer $VANTA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg id "${EXTERNAL_ID_PREFIX}-aggregate" \
                --arg name "Preston-Check Security Audit" \
                --arg result "$result" \
                --argjson score "${score:-0}" \
                --argjson fail "${fail_count:-0}" '{
    external_id: $id,
    name: $name,
    description: "Aggregated Preston-Check pre-deployment security audit. Score and FAIL count.",
    result: $result,
    metadata: {
      score_percent: $score,
      fail_count: $fail,
      tool: "preston-check",
      tool_version: "1.6.0"
    }
  }')" >/dev/null 2>&1 && echo "    OK" || echo "    FAILED"

echo ""
echo "Vanta push complete. Verify in Vanta → Tests → Custom Tests."
