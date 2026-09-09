#!/usr/bin/env bash
###############################################################################
# tap-push.sh — commit and push a Formula update to the Homebrew tap.
#
# Run from inside a checkout of preston-check/homebrew-tap, after the formula
# file has already been rewritten.
#
#   tools/tap-push.sh <version> <commit message>
#
# Exists because a bare `git push` here has two failure modes, both observed:
#
#   1. Transient GitHub errors. Release #461 (run 34290284288) failed with
#      "remote: fatal error in commit_refs" — not a fast-forward rejection,
#      just the far end glitching. One retry would have absorbed it.
#
#   2. Concurrent releases. Draining the promotion backlog on 2026-09-08 fired
#      four releases inside ten minutes, all racing this same ref.
#
# And one hazard the retry must not create: a slow OLDER release must never
# overwrite a NEWER formula. That would leave the tap advertising a version
# whose bottles are stale — the same class of breakage as the September 2026
# bottle outage. Highest version always wins, whichever run finishes last.
###############################################################################
set -euo pipefail

VERSION="${1:?usage: tap-push.sh <version> <commit-message>}"
MESSAGE="${2:?usage: tap-push.sh <version> <commit-message>}"

FORMULA="Formula/preston-check.rb"
ATTEMPTS="${TAP_PUSH_ATTEMPTS:-5}"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"

# Version currently published in the tap, read from the remote-tracking ref.
remote_version() {
  git show "origin/${BRANCH}:${FORMULA}" 2>/dev/null \
    | sed -n 's/^[[:space:]]*version "\([^"]*\)".*/\1/p' | head -1
}

# true when $1 is strictly newer than $2 under version ordering
newer_than() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

if git diff --quiet && git diff --cached --quiet; then
  echo "Formula already up to date — nothing to push"
  exit 0
fi

# Refuse to publish a stale version BEFORE committing, not only when a push is
# rejected. If a newer release updated the tap before this job checked it out,
# our push is a clean fast-forward that silently downgrades the formula — no
# rejection ever happens, so a retry-path-only guard never fires. Releases run
# back to back (four inside ten minutes on 2026-09-08), so this ordering is
# routine, not exotic.
git fetch --quiet origin "$BRANCH" || true
published="$(remote_version || true)"
if [ -n "$published" ] && newer_than "$published" "$VERSION"; then
  echo "::notice::tap already at ${published}, newer than ${VERSION} — not downgrading"
  exit 0
fi

# Keep our rendered formula so it can be re-applied on top of a moved remote
# without re-running the generator.
OURS="$(mktemp)"
cp "$FORMULA" "$OURS"
trap 'rm -f "$OURS"' EXIT

git config user.name  "preston-check-bot"
git config user.email "bot@preston-check.com"
git add "$FORMULA"
git commit -m "$MESSAGE"

for attempt in $(seq 1 "$ATTEMPTS"); do
  if git push origin "$BRANCH"; then
    echo "tap updated to ${VERSION} (attempt ${attempt})"
    exit 0
  fi

  echo "push failed (attempt ${attempt}/${ATTEMPTS}) — refreshing and retrying"
  git fetch --quiet origin "$BRANCH" || true

  published="$(remote_version || true)"
  if [ -n "$published" ] && newer_than "$published" "$VERSION"; then
    # A newer release won the race. Ours is stale; publishing it would point
    # users at bottles that no longer match the advertised version.
    echo "::notice::tap already at ${published}, newer than ${VERSION} — leaving it alone"
    exit 0
  fi

  # Re-apply our formula on top of whatever the remote now has.
  git reset --quiet --hard "origin/${BRANCH}"
  cp "$OURS" "$FORMULA"
  if git diff --quiet; then
    echo "tap already carries this exact formula — nothing left to push"
    exit 0
  fi
  git add "$FORMULA"
  git commit -m "$MESSAGE"

  sleep $(( attempt * 3 ))
done

echo "::error::could not push ${VERSION} to the tap after ${ATTEMPTS} attempts" >&2
exit 1
