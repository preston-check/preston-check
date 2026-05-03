#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-473
name: PSD2 Knowledge Element (PIN / Password)
description: Verifies the knowledge element of PSD2 SCA — PIN/password meeting strength requirements with anti-bruteforce protections. PSD2 RTS Article 6 governs knowledge element requirements.
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
frameworks: PSD2:2018:Art.97, PSD2-RTS:2018:Art.6
false_positive_rate: medium
performance_class: fast
origin: PSD2 RTS Article 6 — knowledge (something the user knows) as an SCA element.
PRESTON_META

echo "P-473: PSD2 Knowledge Element"

SRC="${SOURCE_DIR:-.}"
knowl=$(grep -rln --include="*.ts" --include="*.js" --include="*.java" --include="*.py" --include="*.go" --include="*.rs" \
  -iE "passwordPolicy|password[_-]strength|password[_-]min[_-]length|bruteforce[_-]protection|account[_-]lockout|max[_-]attempts|throttle[_-]auth" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$knowl" ]] && record "PASS" "P-473 PSD2 knowledge" "$(echo "$knowl" | wc -l | tr -d ' ') password/knowledge protection reference(s)" \
  || record "WARN" "P-473 PSD2 knowledge" "No password policy / brute-force protection patterns detected"
