#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-462
name: RBI Application Security Lifecycle
description: Verifies application security lifecycle controls per RBI CSF — secure SDLC, application security testing, code review evidence, security in deployment pipeline.
category: compliance-evidence
severity: medium
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: true
version: 1.0.0
added_in: 1.3.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: RBI-CSF:2024:AppSec, NIST-CSF:2.0:PR.IP, OWASP-API:2023, CIS-v8:16
false_positive_rate: high
performance_class: fast
origin: RBI CSF application security lifecycle requirements.
PRESTON_META

echo "P-462: RBI Application Security Lifecycle"

SRC="${SOURCE_DIR:-.}"
sdlc=$(grep -rln --include="*.md" --include="*.txt" --include="*.yml" --include="*.yaml" \
  -iE "secure[_-]SDLC|SDLC[_-]policy|code[_-]review[_-]process|application[_-]security[_-]testing|SAST|DAST|threat[_-]modeling" "$SRC" 2>/dev/null | grep -v node_modules || true)
[[ -n "$sdlc" ]] && record "PASS" "P-462 RBI app security" "$(echo "$sdlc" | wc -l | tr -d ' ') SDLC / app security reference(s)" \
  || record "WARN" "P-462 RBI app security" "No application security lifecycle documentation found"
