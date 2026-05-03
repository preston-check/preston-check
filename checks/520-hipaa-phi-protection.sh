#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-520
name: HIPAA PHI Protection in Logs and Storage
description: Detects Protected Health Information (PHI) handled without encryption-at-rest references or appearing in log statements. HIPAA Security Rule requires encryption of ePHI and prohibits incidental disclosure through logging.
category: code-scan
severity: high
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: HIPAA:Security-Rule:164.312, NIST-CSF:2.0:PR.DS-1, CWE:532
cwe: 532
false_positive_rate: high
performance_class: fast
origin: HIPAA Security Rule (45 CFR 164.312) — required for any fintech with health-related billing, HSA, FSA, telehealth payment processing.
PRESTON_META

echo "P-520: HIPAA PHI Protection"

SRC="${SOURCE_DIR:-.}"
phi_logs=$(grep -rn --include="*.java" --include="*.kt" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.rb" --include="*.cs" --include="*.php" \
  -iE "(log\.|console\.|logger\.|fmt\.Print|println!).*(diagnosis|patient_id|medical_record|health_status|prescription|icd[_-]?10|cpt[_-]?code)" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/spec/|node_modules" | head -10 || true)
[[ -n "$phi_logs" ]] && record "FAIL" "P-520 HIPAA PHI logs" "$(echo "$phi_logs" | wc -l | tr -d ' ') log statement(s) reference PHI fields" "$phi_logs" \
  || record "PASS" "P-520 HIPAA PHI logs" "No PHI in observable log statements"
