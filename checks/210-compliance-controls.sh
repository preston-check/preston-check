#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-210
name: Compliance Controls
description: Compliance Controls security check (see COMPLIANCE_MAPPING.md for details).
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
frameworks: PCI-DSS:4.0, SOC2:TSC-2017, ISO-27001:2022, OWASP-API:2023, NIST-CSF:2.0, CIS-v8
PRESTON_META

# P-210: Compliance Controls (SOC2, PCI, AML, GDPR)
echo "P-210: Compliance Controls"
SRC="${SOURCE_DIR:-.}"

auth_all=$(grep -rln --include="$SRC_EXT" '@Secured\|@RolesAllowed\|@PreAuthorize\|SecurityRule' "$SRC" 2>/dev/null | grep -i "controller" | grep -v "test\|Test\|target" | wc -l | tr -d ' ')
if [[ $auth_all -gt 0 ]]; then record "PASS" "P-210 Access control" "$auth_all controllers with auth annotations"; else record "FAIL" "P-210 Access control" "No auth annotations on controllers"; fi

tls_config=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.properties" 'ssl.*enabled\|https\|tls\|SSL_PORT' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$tls_config" ]]; then record "PASS" "P-210 TLS config" "SSL/TLS configuration found"; else record "WARN" "P-210 TLS config" "No SSL/TLS configuration found"; fi

monitoring=$(grep -rn --include="$SRC_EXT" 'alert\|Alert\|monitor\|Monitor\|detection\|Detection\|SecurityAuditLogger\|HackingDetection' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|AlertDialog\|AlertTriangle" | head -3)
if [[ -n "$monitoring" ]]; then record "PASS" "P-210 Security monitoring" "Security monitoring/detection patterns found"; else record "FAIL" "P-210 Security monitoring" "No security monitoring infrastructure"; fi

pci_token=$(grep -rn --include="$SRC_EXT" 'tokenize\|Tokenize\|stripeToken\|paymentMethodId\|card_token\|pm_\|tok_' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
raw_pan=$(grep -rn --include="$SRC_EXT" 'card_number\|cardNumber\|pan\b' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|expand\|pan[ei]l\|company\|Japan" | head -3)
if [[ -n "$pci_token" ]] && [[ -z "$raw_pan" ]]; then record "PASS" "P-210 PCI tokenization" "Card tokenization used, no raw PAN storage"; elif [[ -n "$pci_token" ]]; then record "WARN" "P-210 PCI tokenization" "Tokenization found but potential raw PAN references exist"; else record "WARN" "P-210 PCI tokenization" "No card tokenization patterns found"; fi

aml_threshold=$(grep -rn --include="$SRC_EXT" '10000\|threshold\|ctr\|CTR\|suspicious.*activity\|SAR\|structur' "$SRC" 2>/dev/null | grep -iv "test\|Test\|target\|node_modules\|css\|html\|//\|port\|timeout\|size\|max.*page" | head -3)
if [[ -n "$aml_threshold" ]]; then record "PASS" "P-210 AML thresholds" "AML/CTR threshold monitoring patterns found"; else record "WARN" "P-210 AML thresholds" "No AML threshold monitoring — BSA requires CTR for transactions over $10,000"; fi

consent=$(grep -rn --include="$SRC_EXT" 'consent\|terms.*accept\|privacy.*accept\|opt.in\|opt.out\|Terms' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$consent" ]]; then record "PASS" "P-210 Consent tracking" "Consent/terms acceptance patterns found"; else record "WARN" "P-210 Consent tracking" "No consent tracking patterns — GDPR requires documented consent"; fi
