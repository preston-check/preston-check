#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-240
name: Api Security
description: Api Security security check (see COMPLIANCE_MAPPING.md for details).
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

# P-240: API Security
echo "P-240: API Security"
SRC="${SOURCE_DIR:-.}"

validation=$(grep -rn --include="$SRC_EXT" '@Valid\|@NotNull\|@NotBlank\|@NotEmpty\|@Min\|@Max\|@Size\|@Pattern\|validate\|Validator' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | wc -l | tr -d ' ')
if [[ $validation -gt 5 ]]; then record "PASS" "P-240 Input validation" "$validation validation annotations/patterns found"; else record "WARN" "P-240 Input validation" "Few input validation patterns — all API inputs should be validated"; fi

content_type=$(grep -rn --include="$SRC_EXT" '@Consumes\|@Produces\|MediaType\|Content-Type\|application/json' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | wc -l | tr -d ' ')
if [[ $content_type -gt 5 ]]; then record "PASS" "P-240 Content-Type" "$content_type content type declarations found"; else record "WARN" "P-240 Content-Type" "Few content type declarations — enforce JSON on all endpoints"; fi

pagination=$(grep -rn --include="$SRC_EXT" 'page.*size\|pageSize\|limit.*50\|limit.*100\|maxResults\|per_page\|LIMIT' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules\|//\|/\*" | head -3)
if [[ -n "$pagination" ]]; then record "PASS" "P-240 Pagination limits" "Pagination/result limiting patterns found"; else record "WARN" "P-240 Pagination limits" "No pagination limits — unbounded queries can cause OOM"; fi

sensitive_exclude=$(grep -rn --include="$SRC_EXT" '@JsonIgnore\|@JsonProperty.*access.*WRITE\|transient.*password\|excludeFromResponse\|password.*serialize.*false' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$sensitive_exclude" ]]; then record "PASS" "P-240 Response filtering" "Sensitive field exclusion from serialization found"; else record "WARN" "P-240 Response filtering" "No @JsonIgnore on sensitive fields — passwords/keys may leak in API responses"; fi

idempotency_hdr=$(grep -rn --include="$SRC_EXT" 'Idempotency.Key\|idempotency.key\|IdempotencyKey\|idempotent\|FinancialOperationGuard' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$idempotency_hdr" ]]; then record "PASS" "P-240 Idempotency" "Idempotency key patterns found"; else record "FAIL" "P-240 Idempotency" "No idempotency patterns — POST retries create duplicate operations"; fi

versioning=$(grep -rn --include="$SRC_EXT" --include="*.yml" '/api/v[0-9]\|/v[0-9]/\|@Version\|api.*version' "$SRC" 2>/dev/null | grep -v "test\|Test\|target\|node_modules" | head -3)
if [[ -n "$versioning" ]]; then record "PASS" "P-240 API versioning" "API versioning patterns found"; else record "WARN" "P-240 API versioning" "No API versioning — breaking changes will affect all clients"; fi
