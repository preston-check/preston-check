#!/usr/bin/env python3
"""tools/discover_feeds.py

Daily RSS feed discovery for the threat-intel pipeline. Tests candidate
feed URLs from tools/feed_candidates.txt, checks each for:
  1. Reachability (HTTP 200 or redirect to valid XML)
  2. Valid RSS 2.0 or Atom 1.0 XML
  3. Security/fraud relevance (title or description contains known keywords)
  4. Not already present in ingest_sources.py _RSS_FEEDS

New feeds that pass all checks are appended to the appropriate section
of _RSS_FEEDS in tools/ingest_sources.py so the change lands in source
control on the next commit.

Usage:
  python3 tools/discover_feeds.py [--dry-run] [--json]
  python3 tools/discover_feeds.py --check-url <url>

Exit code: 0 always (non-fatal — a feed lookup failure should not break CI).
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
SOURCES_FILE = ROOT / "tools" / "ingest_sources.py"
CANDIDATES_FILE = ROOT / "tools" / "feed_candidates.txt"

HTTP_TIMEOUT = 20
USER_AGENT = "preston-check-feed-discovery/1.0 (+https://preston-check.com/)"

_SECURITY_KEYWORDS = (
    "vulnerability", "exploit", "breach", "malware", "ransomware",
    "phishing", "fraud", "attack", "cve-", "zero-day", "zero day",
    "rce", "injection", "authentication", "authorization",
    "payment", "fintech", "banking", "threat", "advisory",
    "patch", "disclosure", "apt", "supply chain", "backdoor",
    "botnet", "credential", "data leak", "scam", "bypass",
    "infostealer", "campaign", "nation-state", "threat actor",
    "ioc", "c2 ", "lateral movement", "privilege escalation",
    "unauthorized access", "security flaw", "critical flaw",
    "proof of concept", "poc ", "cvss", "zero-day",
)

_ATOM_NS = "http://www.w3.org/2005/Atom"


def _fetch(url: str) -> tuple[int, str]:
    """Return (status_code, body_text). Returns (0, '') on network error."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, */*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.status, resp.read(256_000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return 0, ""
    except Exception:
        return 0, ""


def _is_valid_feed(text: str) -> bool:
    text = text.lstrip()
    if not text.startswith("<"):
        return False
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return False
    tag = root.tag
    return (
        tag == "rss"
        or tag.endswith("}rss")
        or tag == f"{{{_ATOM_NS}}}feed"
        or tag == "feed"
    )


def _extract_titles(text: str, max_items: int = 5) -> list[str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    titles: list[str] = []
    tag = root.tag
    if tag == "rss" or tag.endswith("}rss"):
        for item in root.findall(".//item")[:max_items]:
            t = item.findtext("title") or ""
            titles.append(t.strip())
    else:
        for entry in root.findall(f".//{{{_ATOM_NS}}}entry")[:max_items]:
            el = entry.find(f"{{{_ATOM_NS}}}title")
            if el is not None and el.text:
                titles.append(el.text.strip())
    return titles


def _is_relevant(titles: list[str]) -> bool:
    combined = " ".join(titles).lower()
    combined = re.sub(r"<[^>]+>", " ", combined)
    combined = html.unescape(combined)
    return any(kw in combined for kw in _SECURITY_KEYWORDS)


def _existing_urls() -> set[str]:
    """Parse _RSS_FEEDS from ingest_sources.py and return the set of known URLs."""
    src = SOURCES_FILE.read_text()
    return set(re.findall(r'"(https?://[^"]+)"', src[src.find("_RSS_FEEDS"):src.find("_RSS_SECURITY_KEYWORDS")]))


def _url_to_slug(url: str) -> str:
    """Derive a short readable slug from a URL."""
    host = re.sub(r"^www\.", "", re.sub(r"https?://", "", url).split("/")[0])
    host = re.sub(r"\.[a-z]{2,}$", "", host).replace(".", "_")
    return re.sub(r"[^a-z0-9_]", "", host.lower())[:24] or "feed"


def _ensure_unique_slug(slug: str, existing_slugs: set[str]) -> str:
    base = slug
    n = 2
    while slug in existing_slugs:
        slug = f"{base}_{n}"
        n += 1
    return slug


def _existing_slugs() -> set[str]:
    src = SOURCES_FILE.read_text()
    block = src[src.find("_RSS_FEEDS"):src.find("_RSS_SECURITY_KEYWORDS")]
    return set(re.findall(r'\("([a-z0-9_]+)",', block))


def _append_feed(slug: str, url: str, section_comment: str) -> None:
    """Append (slug, url) to _RSS_FEEDS in ingest_sources.py under the
    closest matching section comment. Falls back to appending before the closing ]."""
    src = SOURCES_FILE.read_text()
    entry = f'    ("{slug}", "{url}"),\n'
    # Try to insert after the section comment line
    if section_comment and section_comment in src:
        insert_after = src.index(section_comment) + len(section_comment)
        next_nl = src.index("\n", insert_after)
        src = src[: next_nl + 1] + entry + src[next_nl + 1 :]
    else:
        # Append before the closing ] of _RSS_FEEDS
        close = src.rindex("]", 0, src.find("_RSS_SECURITY_KEYWORDS"))
        src = src[:close] + entry + src[close:]
    SOURCES_FILE.write_text(src)


def check_one(url: str) -> dict[str, Any]:
    status, body = _fetch(url)
    if status == 0:
        return {"url": url, "ok": False, "reason": "network error"}
    if not _is_valid_feed(body):
        return {"url": url, "ok": False, "reason": f"not valid RSS/Atom (HTTP {status})"}
    titles = _extract_titles(body)
    if not titles:
        return {"url": url, "ok": False, "reason": "no items in feed"}
    if not _is_relevant(titles):
        return {"url": url, "ok": False, "reason": "no security-relevant content", "sample": titles[:2]}
    return {"url": url, "ok": True, "sample": titles[:2]}


def load_candidates() -> list[tuple[str, str | None]]:
    """Read feed_candidates.txt, return list of (url, label_or_None)."""
    if not CANDIDATES_FILE.is_file():
        return []
    entries: list[tuple[str, str | None]] = []
    for raw in CANDIDATES_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        url = parts[0]
        label = parts[1] if len(parts) > 1 else None
        entries.append((url, label))
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover and add new security RSS feeds.")
    parser.add_argument("--dry-run", action="store_true", help="Check but do not modify ingest_sources.py")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    parser.add_argument("--check-url", metavar="URL", help="Check a single URL and exit")
    args = parser.parse_args()

    if args.check_url:
        result = check_one(args.check_url)
        import json as _json
        print(_json.dumps(result, indent=2))
        return 0

    candidates = load_candidates()
    if not candidates:
        print("No candidates in feed_candidates.txt", file=sys.stderr)
        return 0

    existing_urls = _existing_urls()
    existing_slugs = _existing_slugs()

    added: list[dict] = []
    skipped_already: int = 0
    failed: list[dict] = []

    for url, label in candidates:
        if url in existing_urls:
            skipped_already += 1
            continue

        result = check_one(url)
        if not result["ok"]:
            failed.append(result)
            continue

        slug = label or _url_to_slug(url)
        slug = _ensure_unique_slug(slug, existing_slugs)
        existing_slugs.add(slug)
        existing_urls.add(url)

        entry = {"slug": slug, "url": url, "sample": result.get("sample", [])}
        added.append(entry)

        if not args.dry_run:
            _append_feed(slug, url, "# Developer / supply chain security")
            print(f"  + added {slug} <- {url}")
        else:
            print(f"  [dry-run] would add {slug} <- {url}")

    if args.json:
        import json as _json
        print(_json.dumps({
            "added": len(added),
            "skipped_already_present": skipped_already,
            "failed": len(failed),
            "new_feeds": added,
        }, indent=2))
    else:
        print(f"\nDiscovery complete: {len(added)} new feeds added, "
              f"{skipped_already} already present, {len(failed)} failed")

    return 0


if __name__ == "__main__":
    sys.exit(main())
