#!/bin/bash
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
  record "WARN" "P-60 Email authentication" "No SPF/DKIM/DMARC configuration references found"
fi

# Check for email template injection
email_injection=$(grep -rn --include="*.java" --include="*.ts" \
  "setText.*\\+\|setSubject.*\\+\|MimeMessage.*\\+\|sendEmail.*\\+" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -z "$email_injection" ]]; then
  record "PASS" "P-60 Email injection" "No email header injection patterns found"
else
  count=$(echo "$email_injection" | wc -l | tr -d ' ')
  record "WARN" "P-60 Email injection" "$count potential email injection sites (string concatenation in email headers)"
fi
