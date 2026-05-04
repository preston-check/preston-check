---
title: "GitHub Release Manual"
audience: "operator, downstream packagers, security auditors"
date: "2026-05-04"
---

# GitHub Release

The canonical source of every published Preston-Check version. Every
distribution channel (Homebrew tap, Docker image, install.sh) pulls
from here.

## URL

`https://github.com/preston-check/preston-check/releases`

Latest: `https://github.com/preston-check/preston-check/releases/latest`

## What ships per release

Each tagged version (`v1.7.5`, `v1.7.4`, …) gets a Release object
with three artifacts:

| Asset | Purpose |
|---|---|
| `preston-check-X.Y.Z.tar.gz` | Source tarball — the canonical install medium |
| `preston-check-X.Y.Z.tar.gz.sha256` | SHA-256 sidecar — verify before extracting |
| `install.sh` | POSIX-sh installer — `curl ... \| sh` consumes this |

Plus auto-generated release notes from the merged commits since the
previous tag.

## How releases are produced

`.github/workflows/release.yml` fires on tag push (`v*`). Three jobs:

1. **release** — builds the tarball, computes SHA-256, creates the
   GitHub Release, uploads all three assets
2. **docker** — builds + pushes the multi-arch Docker image to
   Docker Hub (skipped if `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`
   secrets aren't configured)
3. **homebrew** — bumps the formula in `preston-check/homebrew-tap`
   to point at the new tarball + sha256 (skipped if
   `HOMEBREW_TAP_TOKEN` secret isn't configured)

## Cutting a release (operator)

```bash
# 1. Bump PRESTON_VERSION in preston-check.sh
# 2. Update CHANGELOG.md with a new section
# 3. Commit
git commit -m "vX.Y.Z: short summary"
# 4. Tag + push
git tag -a vX.Y.Z -m "vX.Y.Z: summary"
git push origin master --tags
```

The release workflow takes over from there. The Release appears at
`github.com/preston-check/preston-check/releases/tag/vX.Y.Z` within
30-60 seconds.

## Verifying a release (downstream consumers)

```bash
VERSION=1.7.5
curl -fsSL "https://github.com/preston-check/preston-check/releases/download/v${VERSION}/preston-check-${VERSION}.tar.gz" -o pc.tar.gz
curl -fsSL "https://github.com/preston-check/preston-check/releases/download/v${VERSION}/preston-check-${VERSION}.tar.gz.sha256" -o pc.tar.gz.sha256

# Verify
echo "$(awk '{print $1}' pc.tar.gz.sha256)  pc.tar.gz" | shasum -a 256 -c
# Expected: pc.tar.gz: OK

# Extract
tar -xzf pc.tar.gz
```

The `install.sh` script does this verification automatically.
Customers who can't or won't trust `install.sh` can do the same
verification by hand.

## Release notes

`generate_release_notes: true` is set in `release.yml`, so GitHub
auto-generates notes from the commits between tags using its
default classifier (Features, Bug Fixes, Other).

The CHANGELOG entry in the repo is the canonical narrative; the
auto-generated release notes are a deduplicated commit list. Both
are useful — the CHANGELOG for "what changed and why," the
auto-notes for "every commit that landed."

## Release cadence

No fixed schedule. Tags ship when something material lands:

- **Patch (1.7.x)** for bug fixes, doc updates, small additions
- **Minor (1.x.0)** for new checks, new frameworks, new flags,
  meaningful new features
- **Major (x.0.0)** reserved for breaking changes (none planned)

Empirically, recent cadence is ~5 patches per week during active
development, dropping to ~1 patch per week steady-state.

## Yanking a release

If a release introduces a regression that needs urgent rollback:

1. **Don't delete the tag** — that breaks downstream consumers
   pinned to it.
2. **Edit the Release on GitHub** — mark it as a pre-release or
   add a prominent "DO NOT USE — see vX.Y.Z+1" warning at the top.
3. **Cut a hotfix immediately** — `vX.Y.Z+1` containing only the
   reverting commit + the underlying fix.
4. **Update the Homebrew tap manually** to point at the hotfix
   if the auto-bump didn't fire.

## Source / public-facing

```
.github/workflows/release.yml      tag-triggered release builder
CHANGELOG.md                       canonical narrative of every release
install.sh                         downstream installer
preston-check.sh                   single-file source of truth for PRESTON_VERSION
```

## Cross-links

- **Homebrew tap manual**: `docs/manuals/homebrew-tap.md`
- **Operator runbook**: `docs/operator-runbook.md`
- **Administrator manual** (release procedure): `docs/manuals/administrator-manual.md`
