#!/bin/bash
# P-41: Dependency Pinning & Lock Files
echo "P-41: Dependency Pinning"
SRC="${SOURCE_DIR:-.}"
maven_unpinned=$(grep -rn --include="pom.xml" --max-count=5 "LATEST\|RELEASE" "$SRC" 2>/dev/null | grep -v "target\|node_modules" | head -3)
if [[ -z "$maven_unpinned" ]]; then record "PASS" "P-41 Maven pinned" "No LATEST/RELEASE Maven versions"; else record "FAIL" "P-41 Maven pinned" "Unpinned Maven versions (LATEST/RELEASE)"; fi
npm_dirs=$(find "$SRC" -maxdepth 3 -name "package.json" -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)
for pkg in $npm_dirs; do
  dir=$(dirname "$pkg")
  if [[ ! -f "$dir/package-lock.json" ]] && [[ ! -f "$dir/yarn.lock" ]]; then
    record "WARN" "P-41 Lock file $(basename $dir)" "No lock file in $(basename $dir)"
  fi
done
docker_latest=$(find "$SRC" -maxdepth 4 -name "Dockerfile*" ! -path "*/target/*" -exec grep -l ":latest\|FROM.*[^:]*$" {} \; 2>/dev/null)
if [[ -z "$docker_latest" ]]; then record "PASS" "P-41 Docker pinned" "No Docker :latest tags"; else record "WARN" "P-41 Docker pinned" "Docker images using :latest tag"; fi
