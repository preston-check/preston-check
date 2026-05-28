---
title: "Homebrew Tap Manual"
audience: "operator, end users installing via Homebrew"
date: "2026-05-04"
---

# Homebrew Tap

The Homebrew formula that lets users `brew install preston-check`. A
separate repo from the main one because Homebrew expects taps to be
their own repos.

## Repo

`https://github.com/preston-check/homebrew-tap`

## Installing from the tap (end user)

```bash
brew tap preston-check/tap
brew install preston-check
```

After the first install, future updates land via:

```bash
brew update && brew upgrade preston-check
```

## What's in the tap

```
homebrew-tap/
  Formula/
    preston-check.rb     the only formula in the tap
  README.md              tap installation notes (visible to users)
  LICENSE                Apache 2.0
```

The formula at `Formula/preston-check.rb` is a Ruby class extending
`Formula`. Three fields change per release: `url`, `sha256`, `version`.
Everything else is stable.

## How it gets bumped

Two paths.

**Auto-bump (preferred)** — The `release.yml` workflow in the main
repo has a `homebrew` job that runs after a successful release. It
checks out the tap repo using a `HOMEBREW_TAP_TOKEN` secret (a PAT
with write access to the tap), rewrites `url` / `sha256` / `version`
in the formula, commits, and pushes. End-to-end ~30 seconds after
the release fires.

The PAT is scoped to "Contents: Write" on the homebrew-tap repo
only. Set as a repo secret named `HOMEBREW_TAP_TOKEN` in the main
preston-check repo (Settings → Secrets and variables → Actions).

**Manual bump (fallback)** — If `HOMEBREW_TAP_TOKEN` isn't set or
the auto-bump fails:

```bash
SHA=$(curl -fsSL https://github.com/preston-check/preston-check/releases/download/vX.Y.Z/preston-check-X.Y.Z.tar.gz.sha256 | awk '{print $1}')
git clone https://github.com/preston-check/homebrew-tap /tmp/hb
cd /tmp/hb

# Edit Formula/preston-check.rb — change url, sha256, version
# Or use a one-liner via Python:
python3 - <<EOF
import re, pathlib
p = pathlib.Path("Formula/preston-check.rb")
src = p.read_text()
src = re.sub(r'url ".*?"', 'url "https://github.com/preston-check/preston-check/releases/download/vX.Y.Z/preston-check-X.Y.Z.tar.gz"', src, count=1)
src = re.sub(r'sha256 ".*?"', f'sha256 "$SHA"', src, count=1)
src = re.sub(r'version ".*?"', 'version "X.Y.Z"', src, count=1)
p.write_text(src)
EOF

git add Formula/preston-check.rb
git commit -m "preston-check X.Y.Z"
git push
```

## Formula structure

```ruby
class PrestonCheck < Formula
  desc "Pre-deployment security audit for fintech and financial systems"
  homepage "https://preston-check.com"
  url "https://github.com/preston-check/preston-check/releases/download/v1.7.5/preston-check-1.7.5.tar.gz"
  sha256 "<sha256-of-release-tarball>"
  license "Apache-2.0"
  version "1.7.5"

  depends_on "bash"
  depends_on "openssl@3"
  depends_on "gawk"
  depends_on "grep"
  depends_on "coreutils"

  def install
    libexec.install Dir["*"]
    (bin/"preston-check").write <<~SH
      #!/bin/bash
      exec "#{libexec}/preston-check.sh" "$@"
    SH
    chmod 0755, bin/"preston-check"
  end

  def caveats
    <<~EOS
      Preston-Check is installed. Free tier runs without any setup.

      To run a scan in the current directory:
        preston-check

      Documentation: https://preston-check.com
    EOS
  end

  test do
    assert_match "preston-check", shell_output("#{bin}/preston-check --version")
  end
end
```

## Verifying after a bump

```bash
# Force-update the tap's local cache and try install
brew untap preston-check/preston-check 2>/dev/null
brew tap preston-check/tap
brew install preston-check
preston-check --version
# Should print: preston-check 1.7.5 (or whatever the new version is)
```

## Audit trail

Every formula bump becomes a commit on the homebrew-tap repo's master
branch. Easy to inspect: `git log Formula/preston-check.rb` shows
every version change with timestamp and message.

## When something goes wrong

**Install fails with sha256 mismatch** — the release tarball was
modified after the formula was bumped (unlikely; GitHub doesn't
mutate published artifacts) or the formula has the wrong sha256.
Pull the actual sha from the release sidecar and update.

**Install fails with download error** — the release URL doesn't exist
yet. The auto-bump may have raced ahead of GitHub's CDN propagation;
wait 1-2 min and retry.

**Tap returns 404 on tap** — the tap repo was renamed or made
private. Verify `https://github.com/preston-check/homebrew-tap`
loads.

## Cross-links

- **GitHub Release manual**: `docs/manuals/github-release.md`
- **Operator runbook** (manual bump procedure): `docs/operator-runbook.md`
- **Administrator manual** (release flow): `docs/manuals/administrator-manual.md`
