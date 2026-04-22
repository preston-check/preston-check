#!/bin/bash
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
  record "WARN" "P-24 Redis TTL" "$redis_no_ttl Redis set operations may lack TTL"
fi

erasure=$(grep -rn --include="*.java" --include="*.sql" \
  "anonymize\|pseudonymize\|right.*erasure\|GDPR\|deletePersonalData\|purge.*pii\|data.*retention" \
  "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$erasure" ]]; then
  record "PASS" "P-24 Data erasure" "Data deletion/anonymization mechanism found"
else
  record "WARN" "P-24 Data erasure" "No GDPR right-to-erasure mechanism found"
fi
