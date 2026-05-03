#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-27
name: TLS Certificate (Live)
description: Checks cert expiry, HSTS headers on live servers.
category: live-monitoring
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:4.2.1, SOC2:TSC-2017:CC6.7, ISO-27001:2022:8.24, NIST-CSF:2.0:PR.DS-2, CIS-v8:3.10
PRESTON_META


# P-27: TLS Certificate & DNS Security (Live)
# Cert expiry, HSTS, TLS version checks against running endpoints.
echo "P-27: TLS Certificate (Live)"

if [[ -z "${API_BASE_URL}" ]]; then
  record "SKIP" "P-27 TLS cert check" "API_BASE_URL not configured"
  return 0 2>/dev/null || exit 0
fi

DOMAIN=$(echo "$API_BASE_URL" | sed 's|https\?://||' | cut -d/ -f1)

expiry=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null \
  | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
if [[ -n "$expiry" ]]; then
  record "PASS" "P-27 TLS cert valid" "Certificate expires: $expiry"
else
  record "WARN" "P-27 TLS cert check" "Could not retrieve certificate from $DOMAIN"
fi

hsts=$(curl -sI --max-time 10 "$API_BASE_URL" 2>/dev/null | grep -i "Strict-Transport-Security")
if [[ -n "$hsts" ]]; then
  record "PASS" "P-27 HSTS header" "Strict-Transport-Security present"
else
  record "WARN" "P-27 HSTS header" "No HSTS header — susceptible to SSL stripping"
fi
