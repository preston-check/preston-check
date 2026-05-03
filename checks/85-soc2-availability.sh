#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-85
name: Soc2 Availability
description: Soc2 Availability security check (see COMPLIANCE_MAPPING.md for details).
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

# P-85: SOC 2 Availability Criteria (A1)
# Verifies capacity planning, load testing, auto-scaling, and recovery evidence.
echo "P-85: SOC 2 Availability"
SRC="${SOURCE_DIR:-.}"

# Check for capacity planning / load testing
capacity=$(find "$SRC" -maxdepth 5 \( \
  -iname "*capacity*plan*" -o -iname "*load*test*" -o -iname "*stress*test*" \
  -o -iname "*performance*test*" -o -iname "*k6*" -o -iname "*gatling*" -o -iname "*jmeter*" \
  -o -iname "*locust*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -3)
capacity_code=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.json" --include="*.tf" \
  "auto.*scal\|scaling.*policy\|min.*capacity\|max.*capacity\|desired.*count\|target.*utilization" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -n "$capacity" || -n "$capacity_code" ]]; then
  record "PASS" "P-85 Capacity planning" "Capacity planning/load testing evidence found"
else
  record "WARN" "P-85 Capacity planning" "No capacity planning or load testing evidence (SOC 2 A1.1)"
fi

# Check for SLA / uptime commitment documentation
sla=$(find "$SRC" -maxdepth 5 \( -iname "*sla*" -o -iname "*uptime*" -o -iname "*availability*target*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -1)
sla_code=$(grep -rn --include="*.md" --include="*.yml" "SLA\|uptime.*99\|availability.*target\|RTO\|RPO" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -n "$sla" || -n "$sla_code" ]]; then
  record "PASS" "P-85 SLA documentation" "SLA/uptime commitment documentation found"
else
  record "WARN" "P-85 SLA documentation" "No SLA or uptime commitment documentation (SOC 2 A1.1)"
fi

# Check for environmental / infrastructure redundancy
redundancy=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.tf" --include="*.json" \
  "multi.*az\|redundan\|failover\|replica\|standby\|backup.*region\|cross.*region" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -n "$redundancy" ]]; then
  record "PASS" "P-85 Redundancy" "Infrastructure redundancy patterns found"
else
  record "WARN" "P-85 Redundancy" "No infrastructure redundancy patterns (multi-AZ, failover, replicas)"
fi
