#!/bin/bash
# P-45: Mobile Network Security
echo "P-45: Mobile Network"
SRC="${SOURCE_DIR:-.}"
manifest=$(find "$SRC" -maxdepth 6 -name "AndroidManifest.xml" ! -path "*/target/*" ! -path "*/build/*" 2>/dev/null | head -1)
if [[ -n "$manifest" ]]; then
  cleartext=$(grep "usesCleartextTraffic.*true" "$manifest" 2>/dev/null)
  if [[ -n "$cleartext" ]]; then record "FAIL" "P-45 Android cleartext" "Android allows cleartext HTTP"; else record "PASS" "P-45 Android cleartext" "Android blocks cleartext traffic"; fi
else
  record "SKIP" "P-45 Android cleartext" "No AndroidManifest.xml found"
fi
info_plist=$(find "$SRC" -maxdepth 6 -name "Info.plist" ! -path "*/target/*" ! -path "*/build/*" ! -path "*/Pods/*" 2>/dev/null | head -1)
if [[ -n "$info_plist" ]]; then
  ats=$(grep -A2 "NSAppTransportSecurity" "$info_plist" 2>/dev/null | grep "NSAllowsArbitraryLoads.*true")
  if [[ -n "$ats" ]]; then record "FAIL" "P-45 iOS ATS disabled" "App Transport Security disabled"; else record "PASS" "P-45 iOS ATS" "App Transport Security enabled"; fi
else
  record "SKIP" "P-45 iOS ATS" "No Info.plist found"
fi
