# Sharing the blockchain feed list with wallet-verify

This document describes how the blockchain/crypto subset of the threat-intel
feed registry is shared, local-only, with the sibling `wallet-verify` repo so
both projects work from one source of truth.

## What is shared, and why a generated file

The authority is `_RSS_FEEDS` in `tools/ingest_sources.py`. That list mixes
general security feeds with a blockchain/crypto subset organized under section
comments (audit firms, DeFi hack tracking, blockchain analytics, ecosystem
news, audit competitions, crypto-specific threat trackers, crypto community).
Rather than maintain a second hand-edited copy of those feeds — which would
drift the first time `tools/discover_feeds.py` appends a feed in CI — the
blockchain subset is *generated* from the registry by `tools/export_sources.py`.
Any feed added under one of the blockchain section headers is therefore picked
up automatically on the next export.

The crypto-engineering feeds (PKI, hardware wallet, cryptography standards) and
the crypto-adjacent-but-broader feeds (dark-web intel, malware analysis) are
intentionally excluded; they belong to the full feed list, not the blockchain
subset. Adjust the selection by editing `_BLOCKCHAIN_SECTIONS` in the exporter.

## Files

The exporter writes two copies, both gitignored (local-only — neither is ever
committed):

- `.preston-check/shared/blockchain-sources.json` — the master, in this repo.
  Ignored by the existing `.preston-check/*` rule.
- `<wallet-verify>/lib/security/data/blockchain-sources.json` — the synced
  copy. Ignored by an anchored rule added to wallet-verify's `.gitignore`.

The wallet-verify root defaults to a sibling checkout (`../wallet-verify`) and
can be overridden with the `WALLET_VERIFY_ROOT` environment variable. If
wallet-verify is not present, the master is still written and the script exits
0.

The JSON schema is `preston-check/blockchain-sources@v1`: a top-level object
with `count`, a `categories` map (key → label), and a `feeds` array of
`{slug, url, category}` objects, sorted by category then slug for reproducible
output.

## Keeping it in sync

Two mechanisms, per the chosen setup:

Manual — run the exporter whenever you want to refresh:

```
python3 tools/export_sources.py            # write both copies
python3 tools/export_sources.py --dry-run  # preview, write nothing
python3 tools/export_sources.py --json     # machine-readable summary
```

The writer is idempotent: it compares the existing feed set (ignoring the
timestamp) and only rewrites a file when the feeds or categories actually
change.

Automatic — the opt-in git hooks in `.githooks/` regenerate the export when
`tools/ingest_sources.py` changes. `post-commit` covers feeds you add by hand;
`post-merge` covers feeds that `rss-feed-discovery.yml` commits in CI and you
later `git pull`. Enable the hooks once per clone with
`git config --local core.hooksPath .githooks`. Both hooks are non-fatal: a
missing `python3` or absent wallet-verify checkout is swallowed.

## How wallet-verify consumes it

`wallet-verify/lib/security/data/blockchain-sources.ts` loads the JSON at
runtime with `fs.readFileSync` (mirroring the existing `l3-predictive.ts`
pattern). Because the JSON is gitignored — and therefore absent on fresh
clones, CI, and prod builds until synced — the loader degrades gracefully to an
empty list with `fromFile: false` and a `warn` log, rather than throwing. It
exposes `loadBlockchainSources()`, `getFeedsByCategory()`, and `getFeedUrls()`.
