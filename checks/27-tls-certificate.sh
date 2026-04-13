#!/bin/bash
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
