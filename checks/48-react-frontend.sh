#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-48
name: React Frontend
description: Checks dangerouslySetInnerHTML, localStorage tokens.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:6.4.1, SOC2:TSC-2017:CC6.1, ISO-27001:2022:8.26, OWASP-API:2023:API8
PRESTON_META


# P-48: React/TypeScript Frontend Security
echo "P-48: Frontend Security"
SRC="${SOURCE_DIR:-.}"
# OPS_PORTAL_DIR may point at an admin/ops UI source tree; if unset we fall
# back to scanning $SRC (any React/TypeScript frontend in the project will
# be picked up). The previous hard-coded personal path has been removed.
OPS_SRC="${OPS_PORTAL_DIR:-$SRC}"
if [[ ! -d "$OPS_SRC" ]]; then record "SKIP" "P-48 Frontend security" "No frontend source dir found (set OPS_PORTAL_DIR or SOURCE_DIR)"; return 0 2>/dev/null || exit 0; fi
dangerous=$(grep -rn --include="*.tsx" --include="*.jsx" "dangerouslySetInnerHTML" "$OPS_SRC" 2>/dev/null | grep -v "node_modules\|dist")
if [[ -z "$dangerous" ]]; then record "PASS" "P-48 No dangerouslySetInnerHTML" "No XSS via dangerouslySetInnerHTML"; else count=$(echo "$dangerous" | wc -l); record "WARN" "P-48 dangerouslySetInnerHTML" "$count uses of dangerouslySetInnerHTML"; echo "$dangerous" | head -5; fi
token_storage=$(grep -rn --include="*.ts" --include="*.tsx" "localStorage.*token\|localStorage.*jwt\|localStorage.*auth" "$OPS_SRC" 2>/dev/null | grep -v "node_modules\|dist" | head -3)
if [[ -z "$token_storage" ]]; then record "PASS" "P-48 No localStorage tokens" "No tokens in localStorage"; else record "WARN" "P-48 localStorage tokens" "Tokens stored in localStorage (XSS risk)"; fi
