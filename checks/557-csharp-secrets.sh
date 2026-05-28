#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-557
name: C# / .NET Hardcoded Secrets and Connection Strings
description: Detects hardcoded API keys, passwords, and connection strings with credentials in C# source files. .NET code should use IConfiguration, Azure Key Vault, AWS Secrets Manager, or environment variables.
category: code-scan
severity: critical
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 1.0.0
added_in: 1.5.0
author_name: Preston-Check Maintainers
author_github: prestoncheck
frameworks: PCI-DSS:4.0:8.6.2, NIST-CSF:2.0:PR.DS-1, CWE:798
cwe: 798
false_positive_rate: medium
performance_class: fast
origin: Hardcoded connection strings remain prevalent in .NET legacy codebases; Azure Key Vault Secrets Manager are the modern replacement.
PRESTON_META

echo "P-557: C# Hardcoded Secrets"

SRC="${SOURCE_DIR:-.}"
cs_count=$(find "$SRC" -name "*.cs" -not -path "*/bin/*" -not -path "*/obj/*" 2>/dev/null | wc -l | tr -d ' ')
[[ "$cs_count" -eq 0 ]] && { record "SKIP" "P-557 C# secrets" "No C# files found"; return 0 2>/dev/null || true; }

hits=$(grep -rn --include="*.cs" -E "(string\s+(connectionString|password|apiKey|secret)\s*=\s*\"[^\"]*Password=|ConnectionString\s*=\s*\"[^\"]*User\s*Id=)" --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" --exclude-dir="dist" --exclude-dir="build" --exclude-dir="target" "$SRC" 2>/dev/null \
  | grep -vE "/test/|/Tests/|/bin/|/obj/" || true)
[[ -n "$hits" ]] && { sample=$(echo "$hits" | head -10); record "FAIL" "P-557 C# secrets" "$(echo "$hits" | wc -l | tr -d ' ') hardcoded credential pattern(s)" "$sample"; } \
  || record "PASS" "P-557 C# secrets" "No hardcoded connection strings / API keys detected"
