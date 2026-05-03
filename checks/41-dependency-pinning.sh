#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-41
name: Dependency Pinning
description: Checks Maven versions, npm lock files, Docker tags.
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
frameworks: PCI-DSS:4.0:6.3.2, SOC2:TSC-2017:CC8.1, ISO-27001:2022:8.25, NIST-CSF:2.0:ID.AM-2, CIS-v8:2.2
PRESTON_META


# P-41: Dependency Pinning & Lock Files
echo "P-41: Dependency Pinning"
SRC="${SOURCE_DIR:-.}"
maven_unpinned=$(grep -rn --include="pom.xml" "LATEST\|RELEASE" "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -z "$maven_unpinned" ]]; then record "PASS" "P-41 Maven pinned" "No LATEST/RELEASE Maven versions"; else record "FAIL" "P-41 Maven pinned" "Unpinned Maven versions (LATEST/RELEASE)"; fi
npm_dirs=$(find "$SRC" -maxdepth 3 -name "package.json" -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)
for pkg in $npm_dirs; do
  dir=$(dirname "$pkg")
  if [[ ! -f "$dir/package-lock.json" ]] && [[ ! -f "$dir/yarn.lock" ]]; then
    record "WARN" "P-41 Lock file $(basename $dir)" "No lock file in $(basename $dir)" "$(echo "$npm_dirs" | head -10)"
  fi
done
docker_latest=$(find "$SRC" -maxdepth 4 -name "Dockerfile*" ! -path "*/target/*" -exec grep -l ":latest\|FROM.*[^:]*$" {} \; 2>/dev/null)
if [[ -z "$docker_latest" ]]; then record "PASS" "P-41 Docker pinned" "No Docker :latest tags"; else record "WARN" "P-41 Docker pinned" "Docker images using :latest tag"; fi
