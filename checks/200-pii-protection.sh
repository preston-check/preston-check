#!/bin/bash
# P-200: PII Protection
echo "P-200: PII Protection"
SRC="${SOURCE_DIR:-.}"

pii_logs=$(grep -rn --include="$SRC_EXT" 'log\.\(info\|warn\|error\|debug\).*\(\.getEmail()\|\.getPhone()\|\.getSsn()\|password\|card_number\|account_number\)' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|vendor\|masked\|mask\|redact\|\\*\\*\\*")
if [[ -z "$pii_logs" ]]; then record "PASS" "P-200 PII in logs" "No direct PII in log statements"; else count=$(echo "$pii_logs" | wc -l | tr -d ' '); record "WARN" "P-200 PII in logs" "$count potential PII in log statements — use masking"; echo "$pii_logs" | head -5; fi

pii_url=$(grep -rn --include="$SRC_EXT" '@Get.*\(email\|ssn\|password\|card_number\)' "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -z "$pii_url" ]]; then record "PASS" "P-200 PII in URLs" "No PII in URL parameters"; else record "FAIL" "P-200 PII in URLs" "PII exposed in URL parameters — use POST body instead"; fi

pii_mask=$(grep -rn --include="$SRC_EXT" 'mask\|redact\|anonymize\|maskPhone\|maskEmail\|\*\*\*' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$pii_mask" ]]; then record "PASS" "P-200 PII masking" "PII masking/redaction patterns found"; else record "WARN" "P-200 PII masking" "No PII masking patterns — sensitive data should be masked in logs and responses"; fi

encrypt_at_rest=$(grep -rn --include="$SRC_EXT" 'encrypt\|AES\|cipher\|@Encrypted\|EncryptionService\|KMS\|secretsmanager' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|vendor" | head -3)
if [[ -n "$encrypt_at_rest" ]]; then record "PASS" "P-200 Encryption at rest" "Encryption patterns found"; else record "WARN" "P-200 Encryption at rest" "No encryption-at-rest patterns for PII fields"; fi

data_retention=$(grep -rn --include="$SRC_EXT" --include="*.sql" 'retention\|purge\|archive\|PARTITION\|ttl\|expire.*days' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$data_retention" ]]; then record "PASS" "P-200 Data retention" "Data retention/purge patterns found"; else record "WARN" "P-200 Data retention" "No data retention policy — regulators require 5-7 year retention for financial records"; fi

gdpr_delete=$(grep -rn --include="$SRC_EXT" 'deleteClient\|eraseData\|rightToErasure\|gdpr.*delete\|forgetMe\|anonymize.*client' "$SRC" 2>/dev/null | grep -v "test\|Test\|target" | head -3)
if [[ -n "$gdpr_delete" ]]; then record "PASS" "P-200 Right to erasure" "GDPR right-to-erasure capability found"; else record "WARN" "P-200 Right to erasure" "No right-to-erasure capability — GDPR Article 17 requirement"; fi
