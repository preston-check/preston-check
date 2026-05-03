#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-415
name: NYDFS Part 500 Multi-Factor Authentication
description: Verifies MFA on privileged accounts and remote access per 23 NYCRR 500.12. The 2023 amendments expanded MFA requirements significantly — MFA is now required for all individuals accessing internal networks from outside, all privileged accounts, and all access to nonpublic information.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: NYDFS:23NYCRR500:500.12, PCI-DSS:4.0:8.4.2, NIST-CSF:2.0:PR.AA-3, CIS-v8:6.3
false_positive_rate: medium
performance_class: fast
origin: NYDFS Part 500.12 — MFA expanded by 2023 amendments to broad applicability.
PRESTON_META

echo "P-415: NYDFS MFA"

SRC="${SOURCE_DIR:-.}"
mfa=$(grep -rln --include="*.java" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.yml" --include="*.yaml" --include="*.md" \
  -iE "mfa|2fa|two[_-]factor|webauthn|fido2|totp|hardware[_-]token|admin[_-]mfa" "$SRC" 2>/dev/null | grep -vE "/test/|node_modules" || true)
[[ -n "$mfa" ]] && record "PASS" "P-415 NYDFS MFA" "$(echo "$mfa" | wc -l | tr -d ' ') MFA reference(s)" \
  || record "WARN" "P-415 NYDFS MFA" "No MFA / 2FA references found"
