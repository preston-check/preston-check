#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-201
name: GraphQL Introspection in Production
description: Detects GraphQL schemas with introspection enabled in production code paths. Introspection lets attackers enumerate every type, field, and mutation in the API, drastically lowering reconnaissance cost and exposing internal naming that should not be public.
category: code-scan
severity: high
languages: typescript, javascript, java
min_tier: pro
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.0.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: OWASP-API:2023:API3, PCI-DSS:4.0:6.5.5, SOC2:TSC-2017:CC6.6
cwe: 200
owasp: API3:2023
false_positive_rate: low
performance_class: fast
origin: Real-world reconnaissance pattern observed in fintech penetration tests; introspection on production GraphQL endpoints is one of the most common API misconfigurations leading to data-model enumeration.
PRESTON_META

echo "P-201: GraphQL Introspection in Production"

SRC="${SOURCE_DIR:-.}"
found=0

# TypeScript / JavaScript: Apollo Server, GraphQL Yoga, Mercurius
ts_hits=$(grep -rn --include="*.ts" --include="*.tsx" --include="*.js" \
  -E "introspection[[:space:]]*:[[:space:]]*true" "$SRC" 2>/dev/null \
  | grep -v "test\|spec\|node_modules\|dist\|\.next" \
  | head -10)

# Java: graphql-java, dgs-framework
java_hits=$(grep -rn --include="*.java" \
  -E "IntrospectionEnabled[[:space:]]*\\([[:space:]]*true|setIntrospectionEnabled\\([[:space:]]*true" "$SRC" 2>/dev/null \
  | grep -v "test\|Test\|target" \
  | head -10)

[[ -n "$ts_hits" ]] && ((found += $(echo "$ts_hits" | wc -l)))
[[ -n "$java_hits" ]] && ((found += $(echo "$java_hits" | wc -l)))

if [[ $found -eq 0 ]]; then
  record "PASS" "P-201 GraphQL introspection" "No introspection-enabled GraphQL configurations found"
else
  record "FAIL" "P-201 GraphQL introspection" "$found GraphQL endpoints with introspection: true"
fi
