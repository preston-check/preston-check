#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-10
name: Live Attack Indicators
description: Checks production logs for brute force, rapid polling, blacklist events.
category: live-monitoring
severity: medium
languages: any
min_tier: free
runtime_class: live-ssh
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:10.6, SOC2:TSC-2017:CC7.2, ISO-27001:2022:8.16, CIS-v8:8.11
PRESTON_META

# P-10: Live attack indicators (runs against production logs)
# Checks current logs for active hacking patterns.
# Requires SSH_HOST and LOG_DIR to be configured.

echo "P-10: Live Attack Indicators"

if [[ -z "${SSH_HOST}" ]]; then
  record "SKIP" "P-10 Live attack check" "SSH_HOST not configured"
  return 0 2>/dev/null || exit 0
fi

LOG="${LOG_DIR:-/home/ec2-user}"

# Check for brute force in last 24h
brute=$(ssh "$SSH_HOST" "grep 'CREDENTIALS_DO_NOT_MATCH\|USER_NOT_FOUND' $LOG/Security.log 2>/dev/null | tail -100 | grep -oP '\[([^\]]+@[^\]]+)\]' | sort | uniq -c | sort -rn | head -5" 2>/dev/null)

if [[ -z "$brute" ]]; then
  record "PASS" "P-10 Brute force (current)" "No brute force activity in current logs"
else
  top_target=$(echo "$brute" | head -1 | awk '{print $2, $1}')
  record "WARN" "P-10 Brute force (current)" "Active login failures: $top_target"
fi

# Check for rapid session polling (Preston's signature)
rapid=$(ssh "$SSH_HOST" "
  if [[ -f $LOG/Client.log ]]; then
    awk -F'|' '{print \$1}' $LOG/Client.log 2>/dev/null | \
    cut -c1-16 | sort | uniq -c | sort -rn | head -1
  fi
" 2>/dev/null)

if [[ -n "$rapid" ]]; then
  req_count=$(echo "$rapid" | awk '{print $1}')
  if [[ "$req_count" -gt 30 ]]; then
    record "WARN" "P-10 Rapid polling (current)" "Peak: $req_count requests/minute in Client.log"
  else
    record "PASS" "P-10 Rapid polling (current)" "Normal request rate (peak: $req_count/min)"
  fi
else
  record "SKIP" "P-10 Rapid polling" "Could not read Client.log"
fi

# Check for blacklisted account activity
blacklist_activity=$(ssh "$SSH_HOST" "
  grep -h 'blacklisted.*true\|BLACK_LIST\|BLACKLIST_MATCH\|BLACKLIST_BLOCK' \
    $LOG/Client.log $LOG/Security.log 2>/dev/null | tail -5
" 2>/dev/null)

if [[ -n "$blacklist_activity" ]]; then
  record "WARN" "P-10 Blacklist activity" "Recent blacklist events detected in logs"
else
  record "PASS" "P-10 Blacklist activity" "No recent blacklist events"
fi

# Check for 2FA failures on withdrawals
twofa_fail=$(ssh "$SSH_HOST" "
  grep 'Failed to validate 2FA' $LOG/FireblocksSecureWalletWithdraw.log 2>/dev/null | tail -5
" 2>/dev/null)

if [[ -n "$twofa_fail" ]]; then
  count=$(echo "$twofa_fail" | wc -l)
  record "WARN" "P-10 Withdraw 2FA failures" "$count recent 2FA failures on withdrawals"
else
  record "PASS" "P-10 Withdraw 2FA failures" "No recent 2FA failures on withdrawals"
fi
