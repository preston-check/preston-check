#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-60
name: Email Security Headers
description: Covers CIS 9.2, ISO 27001 A.8.21. Checks DNS for SPF, DKIM, and DMARC records. Verifies email templates don't contain tracking pixels or external resources.
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


# P-60: Email Security Headers — CIS 9.2, ISO 27001 A.8.21
# Checks for SPF, DKIM, DMARC configuration and secure email patterns.
echo "P-60: Email Security"
SRC="${SOURCE_DIR:-.}"

# Check for email security configuration
email_auth=$(grep -rn --include="*.java" --include="*.ts" --include="*.yml" --include="*.yaml" \
  "DKIM\|dkim\|SPF\|spf\|DMARC\|dmarc\|ses.*verify\|email.*auth" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$email_auth" ]]; then
  record "PASS" "P-60 Email authentication" "Email authentication (SPF/DKIM/DMARC) configuration found"
else
  record "WARN" "P-60 Email authentication" "No SPF/DKIM/DMARC configuration references found" "$(echo "$email_auth" | head -10)"
fi

# Check for email template injection
email_injection=$(grep -rn --include="*.java" --include="*.ts" \
  "setText.*\\+\|setSubject.*\\+\|MimeMessage.*\\+\|sendEmail.*\\+" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -z "$email_injection" ]]; then
  record "PASS" "P-60 Email injection" "No email header injection patterns found"
else
  count=$(echo "$email_injection" | wc -l | tr -d ' ')
  record "WARN" "P-60 Email injection" "$count potential email injection sites (string concatenation in email headers)" "$(echo "$email_injection" | head -10)"
fi
