#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-482
name: 3DS2 TRA / Low-Value / Trusted Beneficiary Exemption Validation
description: Detects use of 3DS2 SCA exemptions (TRA — Transaction Risk Analysis, low-value < €30, recurring payments, trusted beneficiaries). Misuse of exemptions is a common acquirer compliance finding under PSD2 RTS.
category: code-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PSD2-RTS:2018:Art.18, PSD2-RTS:2018:Art.16, PSD2-RTS:2018:Art.13
false_positive_rate: medium
performance_class: fast
origin: PSD2 RTS Articles 13-18 — SCA exemptions and the limits on each.
PRESTON_META

echo "P-482: 3DS2 SCA Exemption Validation"

SRC="${SOURCE_DIR:-.}"
exemp=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "TRA[_-]exemption|low[_-]value[_-]exemption|trusted[_-]beneficiary|recurring[_-]payment[_-]exemption|exemptionStatus|sca[_-]exemption" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$exemp" ]] && record "PASS" "P-482 3DS2 exemptions" "$(echo "$exemp" | wc -l | tr -d ' ') exemption-handling reference(s)" \
  || record "WARN" "P-482 3DS2 exemptions" "No SCA exemption handling detected (TRA, low-value, recurring, trusted)"
