#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-18
name: Data Privacy
description: Checks for plaintext passwords, PII in logs, missing @JsonIgnore.
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
frameworks: PCI-DSS:4.0:3.4, PCI-DSS:4.0:8.3.2, SOC2:TSC-2017:P1.1, SOC2:TSC-2017:CC6.5, ISO-27001:2022:8.11, ISO-27001:2022:8.12, NIST-CSF:2.0:PR.DS-1, CIS-v8:3.12
PRESTON_META


# P-18: Data privacy and PII protection
# Financial platforms must protect personally identifiable information.
# Passwords must be hashed, PII must not be logged in plaintext.

echo "P-18: Data Privacy & PII"

SRC="${SOURCE_DIR:-.}"

# Check for password hashing (not plaintext storage)
password_hash=$(grep -rn --include="$SRC_EXT" \
  "$PASSWORD_HASH_PATTERN" \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | head -5)

if [[ -n "$password_hash" ]]; then
  record "PASS" "P-18 Password hashing" "Password hashing mechanism found"
else
  record "FAIL" "P-18 Password hashing" "No password hashing found — passwords may be stored in plaintext"
fi

# Check for PII in log statements (email, phone, SSN patterns)
pii_in_logs=$(grep -rn --include="$SRC_EXT" \
  'log\.\(info\|error\|warn\|debug\|Info\|Error\|Warn\|Debug\).*\(email\|phone\|ssn\|password\|secret\|token\)' \
  "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|sanitize\|mask\|redact\|vendor\|_test\.go" \
  | wc -l)

if [[ $pii_in_logs -lt 5 ]]; then
  record "PASS" "P-18 PII in logs" "Minimal PII logging ($pii_in_logs patterns)"
else
  record "WARN" "P-18 PII in logs" "$pii_in_logs potential PII fields in log statements (consider masking)"
fi

# Check for password field exclusion from serialization
json_ignore=$(grep -rn --include="$SRC_EXT" -B1 \
  "password\|Password\|password_salt\|passwordSalt" \
  "$SRC" 2>/dev/null \
  | grep "$SENSITIVE_FIELD_PATTERN\|@JsonIgnore\|json:\"-\"\|omitempty" \
  | grep -v "test\|Test\|target\|vendor\|_test\.go" \
  | wc -l)

if [[ $json_ignore -gt 0 ]]; then
  record "PASS" "P-18 Password serialization" "$json_ignore password fields excluded from serialization"
else
  record "WARN" "P-18 Password serialization" "Check that password fields are excluded from serialization"
fi
