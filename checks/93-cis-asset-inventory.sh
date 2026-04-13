#!/bin/bash
# P-93: CIS Control 1 — Enterprise Asset Inventory
# For cloud-native platforms, "assets" are services, instances, databases, and endpoints.
echo "P-93: CIS Asset Inventory"
SRC="${SOURCE_DIR:-.}"

# Check for service inventory/catalog
service_list=$(find "$SRC" -maxdepth 3 \( \
  -iname "services.list" -o -iname "services.yml" -o -iname "services.json" \
  -o -iname "service-catalog*" -o -iname "*infrastructure*" \) \
  -not -path "*/target/*" -not -path "*/node_modules/*" 2>/dev/null | head -3)
terraform=$(find "$SRC" -maxdepth 5 -name "*.tf" -not -path "*/target/*" 2>/dev/null | head -1)
docker=$(find "$SRC" -maxdepth 3 \( -name "docker-compose*" -o -name "Dockerfile" -o -name "ecosystem.config*" \) 2>/dev/null | head -1)

found=0
[[ -n "$service_list" ]] && found=$((found + 1))
[[ -n "$terraform" ]] && found=$((found + 1))
[[ -n "$docker" ]] && found=$((found + 1))

if [[ $found -ge 2 ]]; then
  record "PASS" "P-93 Asset inventory" "Service inventory/infrastructure-as-code found"
elif [[ $found -ge 1 ]]; then
  record "WARN" "P-93 Asset inventory" "Partial asset inventory — add services.list or infrastructure-as-code (CIS Control 1)"
else
  record "WARN" "P-93 Asset inventory" "No asset inventory — create services.list with all deployed services and their ports"
fi

# Check for auto-discovery or monitoring agent
monitoring=$(grep -rn --include="*.yml" --include="*.yaml" --include="*.json" --include="*.java" \
  "cloudwatch\|datadog\|newrelic\|prometheus\|grafana\|nagios\|zabbix\|pagerduty" \
  "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -n "$monitoring" ]]; then
  record "PASS" "P-93 Asset monitoring" "Infrastructure monitoring/discovery tool references found"
else
  record "WARN" "P-93 Asset monitoring" "No infrastructure monitoring tool references (CloudWatch, Datadog, Prometheus)"
fi
