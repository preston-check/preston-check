#!/usr/bin/env python3
"""tools/export_sources.py

Export the blockchain/crypto subset of the threat-intel feed registry to a
single canonical JSON file, and mirror a copy into the sibling wallet-verify
repo so both projects share one source of truth.

The feed registry (`_RSS_FEEDS` in tools/ingest_sources.py) is the authority.
This script never forks that data — it parses the registry and selects the
feeds that live under the blockchain/crypto section headers, so any feed added
under one of those sections (by hand or by tools/discover_feeds.py) is picked
up automatically on the next export.

Outputs (both gitignored — local-only, never committed):
  - <preston-check>/.preston-check/shared/blockchain-sources.json   (master)
  - <wallet-verify>/lib/security/data/blockchain-sources.json       (synced copy)

The wallet-verify root defaults to a sibling checkout (../wallet-verify) and
can be overridden with the WALLET_VERIFY_ROOT environment variable. If it is
absent, the master is still written and the script exits 0 (non-fatal, so the
git hooks that call it can never block a commit or merge).

Usage:
  python3 tools/export_sources.py            # generate + write both copies
  python3 tools/export_sources.py --dry-run  # show what would change, write nothing
  python3 tools/export_sources.py --json     # emit a JSON summary
  python3 tools/export_sources.py --quiet     # suppress normal output (for hooks)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "tools" / "ingest_sources.py"
MASTER_OUT = ROOT / ".preston-check" / "shared" / "blockchain-sources.json"

WALLET_VERIFY_ROOT = Path(
    os.environ.get("WALLET_VERIFY_ROOT", str(ROOT.parent / "wallet-verify"))
)
WALLET_VERIFY_OUT = (
    WALLET_VERIFY_ROOT / "lib" / "security" / "data" / "blockchain-sources.json"
)

SCHEMA = "preston-check/blockchain-sources@v1"

# Section comments in _RSS_FEEDS that are blockchain/crypto-dedicated, mapped to
# a stable category key + human label. A feed is included iff it sits under one
# of these sections. Crypto-adjacent-but-broader sections (dark-web intel,
# malware analysis) and crypto-engineering (PKI, hardware-wallet, cryptography
# standards) are intentionally excluded — they belong to the full feed list,
# not the blockchain subset. Matching is by case-insensitive substring so minor
# edits to the comment text don't silently drop a section.
_BLOCKCHAIN_SECTIONS: list[tuple[str, str, str]] = [
    ("audit firms", "audit-firms", "Blockchain security audit firms"),
    ("defi hack tracking", "defi-hack-tracking", "DeFi exploit tracking & on-chain intelligence"),
    ("blockchain analytics", "analytics", "Blockchain analytics"),
    ("blockchain ecosystem", "ecosystem", "Blockchain ecosystem & industry news"),
    ("audit competition", "audit-competition", "Audit competition platforms"),
    ("crypto-specific threat trackers", "crypto-threat-trackers", "Crypto-specific threat trackers"),
    ("crypto community", "crypto-community", "Crypto community & DeFi security research"),
]

_TUPLE_RE = re.compile(r'^\s*\(\s*"([a-z0-9_]+)"\s*,\s*"(https?://[^"]+)"\s*\)\s*,?\s*$')
_COMMENT_RE = re.compile(r'^\s*#\s*(.+?)\s*$')


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _classify(section: str | None) -> tuple[str, str] | None:
    if not section:
        return None
    low = section.lower()
    for needle, key, label in _BLOCKCHAIN_SECTIONS:
        if needle in low:
            return key, label
    return None


def _parse_registry() -> list[dict]:
    """Parse _RSS_FEEDS and return the blockchain subset as feed dicts.

    Uses the same block boundaries as tools/discover_feeds.py so the two tools
    agree on where the registry starts and ends.
    """
    src = SOURCES_FILE.read_text()
    start = src.find("_RSS_FEEDS")
    end = src.find("_RSS_SECURITY_KEYWORDS")
    if start == -1 or end == -1:
        raise SystemExit("export_sources: could not locate _RSS_FEEDS block in ingest_sources.py")
    block = src[start:end]

    feeds: list[dict] = []
    current_section: str | None = None
    for line in block.splitlines():
        cm = _COMMENT_RE.match(line)
        if cm:
            current_section = cm.group(1)
            continue
        tm = _TUPLE_RE.match(line)
        if not tm:
            continue
        cat = _classify(current_section)
        if cat is None:
            continue
        feeds.append({"slug": tm.group(1), "url": tm.group(2), "category": cat[0]})

    # Stable order for reproducible output (category, then slug).
    feeds.sort(key=lambda f: (f["category"], f["slug"]))
    return feeds


def _build_manifest(feeds: list[dict]) -> dict:
    present = {f["category"] for f in feeds}
    categories = {
        key: label
        for _needle, key, label in _BLOCKCHAIN_SECTIONS
        if key in present
    }
    return {
        "schema": SCHEMA,
        "description": (
            "Blockchain/crypto threat-intel content feeds, generated from "
            "preston-check tools/ingest_sources.py (_RSS_FEEDS). Local-only and "
            "machine-generated — do not edit by hand; run tools/export_sources.py "
            "to refresh."
        ),
        "source_repo": "preston-check",
        "source_file": "tools/ingest_sources.py",
        "count": len(feeds),
        "categories": categories,
        "feeds": feeds,
    }


def _unchanged(path: Path, manifest: dict) -> bool:
    """True if path already holds this feed set (ignoring the timestamp)."""
    if not path.is_file():
        return False
    try:
        existing = json.loads(path.read_text())
    except Exception:
        return False
    return (
        existing.get("feeds") == manifest["feeds"]
        and existing.get("categories") == manifest["categories"]
        and existing.get("count") == manifest["count"]
    )


def _write(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamped = {**manifest, "generated_at": _now_iso()}
    # Order keys so generated_at sits near the top for readability.
    ordered = {
        "schema": stamped["schema"],
        "generated_at": stamped["generated_at"],
        "description": stamped["description"],
        "source_repo": stamped["source_repo"],
        "source_file": stamped["source_file"],
        "count": stamped["count"],
        "categories": stamped["categories"],
        "feeds": stamped["feeds"],
    }
    path.write_text(json.dumps(ordered, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export the blockchain feed subset to a shared JSON file."
    )
    parser.add_argument("--dry-run", action="store_true", help="Show changes, write nothing")
    parser.add_argument("--json", action="store_true", help="Emit a JSON summary")
    parser.add_argument("--quiet", action="store_true", help="Suppress normal output (for git hooks)")
    args = parser.parse_args()

    def info(msg: str) -> None:
        if not args.quiet and not args.json:
            print(msg)

    feeds = _parse_registry()
    manifest = _build_manifest(feeds)

    targets: list[tuple[str, Path, bool]] = [("master", MASTER_OUT, True)]
    if WALLET_VERIFY_ROOT.is_dir():
        targets.append(("wallet-verify", WALLET_VERIFY_OUT, True))
    else:
        print(
            f"export_sources: wallet-verify root not found at {WALLET_VERIFY_ROOT} "
            f"— wrote master only (set WALLET_VERIFY_ROOT to override)",
            file=sys.stderr,
        )

    results: list[dict] = []
    for name, path, _enabled in targets:
        changed = not _unchanged(path, manifest)
        if changed and not args.dry_run:
            _write(path, manifest)
        results.append({"target": name, "path": str(path), "changed": changed})
        verb = "would update" if args.dry_run else ("updated" if changed else "unchanged")
        info(f"  {verb}: {path} ({len(feeds)} feeds)")

    info(
        f"\nExported {len(feeds)} blockchain feeds across "
        f"{len(manifest['categories'])} categories."
    )

    if args.json:
        print(json.dumps({
            "count": len(feeds),
            "categories": list(manifest["categories"].keys()),
            "targets": results,
            "dry_run": args.dry_run,
        }, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
