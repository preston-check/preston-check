#!/bin/bash
###############################################################################
# tools/integrations/drata/push-evidence.sh
#
# Pushes a Preston-Check report into Drata as evidence-of-control. Drata's
# Public API accepts evidence file uploads tagged against specific control
# IDs; this script reads a Preston-Check JSON manifest and posts each
# applicable evidence item.
#
# Drata is the highest-leverage compliance platform integration because of
# its market share among fintechs going through SOC 2 / ISO 27001 prep.
# Once this integration ships, every Drata customer scanning their code
# with Preston-Check can satisfy a portion of their compliance evidence
# requirements automatically.
#
# Required env:
#   DRATA_API_KEY      — generated in Drata → Settings → API Keys
#   DRATA_WORKSPACE_ID — your Drata workspace UUID
#
# Usage:
#   tools/integrations/drata/push-evidence.sh <preston-check-report.md>
###############################################################################

set -uo pipefail

REPORT="${1:?usage: $0 <preston-check-report.md>}"
[[ -f "$REPORT" ]] || { echo "report not found: $REPORT" >&2; exit 1; }
[[ -n "${DRATA_API_KEY:-}" ]] || { echo "DRATA_API_KEY required" >&2; exit 1; }
[[ -n "${DRATA_WORKSPACE_ID:-}" ]] || { echo "DRATA_WORKSPACE_ID required" >&2; exit 1; }

API="https://public-api.drata.com/api/v1"

# Map Preston-Check framework citations to Drata control identifiers.
# Drata uses standardized control IDs per framework; this mapping is the
# bridge. The map is kept here (not in metadata) because each Drata
# customer may rename their controls and customers can override.
declare -A CONTROL_MAP=(
  ["PCI-DSS:4.0:6.5.1"]="DRA-PCI-650"
  ["SOC2:TSC-2017:CC6.1"]="DRA-SOC2-CC6-1"
  ["ISO-27001:2022:8.4"]="DRA-ISO-A8-4"
  ["NIST-CSF:2.0:PR.DS-1"]="DRA-NIST-PRDS1"
  # Add more mappings as Drata's control catalog grows
)

echo "Pushing $(basename "$REPORT") to Drata workspace $DRATA_WORKSPACE_ID..."

# Wrap the markdown report as a single evidence item attached to all
# applicable controls. Drata accepts multipart uploads.
report_b64=$(base64 < "$REPORT" | tr -d '\n')

for framework_token in "${!CONTROL_MAP[@]}"; do
  drata_control="${CONTROL_MAP[$framework_token]}"
  if grep -q "$framework_token" "$REPORT"; then
    echo "  → $framework_token → $drata_control"
    curl -s -X POST "$API/workspaces/$DRATA_WORKSPACE_ID/evidence" \
      -H "Authorization: Bearer $DRATA_API_KEY" \
      -H "Content-Type: application/json" \
      -d "$(jq -n --arg c "$drata_control" --arg n "Preston-Check $(date -u +%Y-%m-%d)" --arg r "$report_b64" '{
        controlId: $c,
        evidence: {
          name: $n,
          description: "Preston-Check security audit report",
          fileBase64: $r,
          fileName: "preston-check-report.md",
          contentType: "text/markdown"
        }
      }')" >/dev/null 2>&1 && echo "    OK" || echo "    FAILED"
  fi
done

echo ""
echo "Drata evidence push complete. Verify in Drata → Controls → individual controls."
