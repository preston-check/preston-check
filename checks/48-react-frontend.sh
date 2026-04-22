#!/bin/bash
# P-48: React/TypeScript Frontend Security
echo "P-48: Frontend Security"
SRC="${SOURCE_DIR:-.}"
OPS_SRC="${OPS_PORTAL_DIR:-}"
[[ -z "$OPS_SRC" ]] && OPS_SRC="/Users/diegofbaez/DEV/operations/BloxOpsPortal/client/src"
if [[ ! -d "$OPS_SRC" ]]; then record "SKIP" "P-48 Frontend security" "Ops portal not found"; return 0 2>/dev/null || exit 0; fi
dangerous=$(grep -rn --include="*.tsx" --include="*.jsx" "dangerouslySetInnerHTML" "$OPS_SRC" 2>/dev/null | grep -v "node_modules\|dist")
if [[ -z "$dangerous" ]]; then record "PASS" "P-48 No dangerouslySetInnerHTML" "No XSS via dangerouslySetInnerHTML"; else count=$(echo "$dangerous" | wc -l); record "WARN" "P-48 dangerouslySetInnerHTML" "$count uses of dangerouslySetInnerHTML"; echo "$dangerous" | head -5; fi
token_storage=$(grep -rn --include="*.ts" --include="*.tsx" "localStorage.*token\|localStorage.*jwt\|localStorage.*auth" "$OPS_SRC" 2>/dev/null | grep -v "node_modules\|dist" | head -3)
if [[ -z "$token_storage" ]]; then record "PASS" "P-48 No localStorage tokens" "No tokens in localStorage"; else record "WARN" "P-48 localStorage tokens" "Tokens stored in localStorage (XSS risk)"; fi
