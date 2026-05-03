#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-24
name: Data Retention
description: Checks Redis without TTL, GDPR erasure mechanisms.
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
frameworks: PCI-DSS:4.0:3.2.1, SOC2:TSC-2017:P4.1, ISO-27001:2022:8.10, NIST-CSF:2.0:PR.DS-3, CIS-v8:3.4
PRESTON_META


# P-24: Data Retention & Right to Deletion
# Redis TTL, GDPR erasure, retention policies.
echo "P-24: Data Retention"
SRC="${SOURCE_DIR:-.}"

redis_no_ttl=$(grep -rn --include="*.java" \
  "jedis.*set\|addHash\|hset" "$SRC/Common/src" 2>/dev/null \
  | grep -v "test\|Test\|target\|expire\|TTL\|timeout\|EXPIRE\|setex" | wc -l)
if [[ $redis_no_ttl -lt 3 ]]; then
  record "PASS" "P-24 Redis TTL" "Redis operations use TTL/expiration"
else
  record "WARN" "P-24 Redis TTL" "$redis_no_ttl Redis set operations may lack TTL" "$(echo "$redis_no_ttl" | head -10)"
fi

erasure=$(grep -rn --include="*.java" --include="*.sql" \
  "anonymize\|pseudonymize\|right.*erasure\|GDPR\|deletePersonalData\|purge.*pii\|data.*retention" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$erasure" ]]; then
  record "PASS" "P-24 Data erasure" "Data deletion/anonymization mechanism found"
else
  record "WARN" "P-24 Data erasure" "No GDPR right-to-erasure mechanism found" "$(echo "$erasure" | head -10)"
fi
