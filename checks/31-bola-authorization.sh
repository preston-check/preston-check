#!/bin/bash
# P-31: Broken Object Level Authorization (BOLA) — OWASP API #1
echo "P-31: BOLA Authorization"
SRC="${SOURCE_DIR:-.}"

controllers=$(find "$SRC" -name "*Controller.java" -path "*/src/*" ! -path "*/test/*" ! -path "*/target/*" 2>/dev/null)
bola_risk=0
for c in $controllers; do
  has_id=$(grep -c '{clientId}\|{userId}\|{portfolioId}\|{accountId}' "$c" 2>/dev/null)
  if [[ "$has_id" -gt 0 ]]; then
    has_ownership=$(grep -c 'session\.getClient_id\|authenticatedClient\|getClientFromSession\|verifyAccess\|BxxSecurityUtils.extractClient' "$c" 2>/dev/null)
    if [[ "$has_ownership" -eq 0 ]]; then
      ((bola_risk++))
    fi
  fi
done

if [[ $bola_risk -eq 0 ]]; then
  record "PASS" "P-31 BOLA checks" "Controllers with ID params have ownership validation"
else
  record "WARN" "P-31 BOLA checks" "$bola_risk controllers accept resource IDs without ownership verification"
fi
