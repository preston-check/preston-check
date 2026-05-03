#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-26
name: Network Exposure
description: Checks Redis without auth, management ports exposed.
category: infra-scan
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 0.1.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:1.3, PCI-DSS:4.0:2.2.4, SOC2:TSC-2017:CC6.6, ISO-27001:2022:8.20, ISO-27001:2022:8.21, NIST-CSF:2.0:PR.AC-5, CIS-v8:12.2
PRESTON_META


# P-26: Network Exposure & Port Security
# 0.0.0.0 binding, Redis auth, JMX, public DB endpoints.
echo "P-26: Network Exposure"
SRC="${SOURCE_DIR:-.}"

redis_no_auth=$(grep -rn --include="*.yml" --include="*.yaml" \
  "redis.*host\|redis.*server\|redis.*url" "$SRC" 2>/dev/null \
  | grep -v "password\|auth\|requirepass\|test\|Test\|target\|#" | head -5)
redis_with_auth=$(grep -rn --include="*.yml" --include="*.yaml" \
  "redis.*password\|redis.*auth" "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|#" | head -3)
if [[ -n "$redis_with_auth" ]]; then
  record "PASS" "P-26 Redis auth" "Redis authentication configured"
elif [[ -n "$redis_no_auth" ]]; then
  record "WARN" "P-26 Redis auth" "Redis connections without password found" "$(echo "$redis_with_auth" | head -10)"
else
  record "SKIP" "P-26 Redis auth" "No Redis configuration found"
fi

mgmt_ports=$(grep -rn --include="*.yml" --include="*.yaml" \
  "jmx.*port\|management.*port\|actuator\|jolokia" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|#\|disabled\|false" | head -3)
if [[ -z "$mgmt_ports" ]]; then
  record "PASS" "P-26 No mgmt ports" "No exposed management/debug ports"
else
  record "WARN" "P-26 Mgmt ports" "Management/debug ports may be exposed" "$(echo "$mgmt_ports" | head -10)"
fi
