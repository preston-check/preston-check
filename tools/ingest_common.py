#!/usr/bin/env python3
"""tools/ingest_common.py

Shared helpers for the threat-intel ingestion layer. Every source
ingester (reactive: KEV, GHSA, NVD, OSV; proactive tier 1: GitHub
trending, abuse.ch, Reddit, Mastodon, oss-security mailing list,
ZDI; tier-3 stub: partner feed) goes through the helpers here for:

  - Per-source state persistence under .preston-check/state/{source}.json
  - Per-source queue output under .preston-check/queue/{source}-{ts}.json
  - HTTP fetch with timeout, user-agent, and basic retry
  - The CandidateRecord schema (the normalised intermediate object the
    synthesizer consumes regardless of which source produced it)
  - Per-source budget tracking against per-day USD caps

The threat model (M1) requires per-source state isolation so concurrent
runs across sources can't corrupt each other; this is enforced
structurally by the path layout — there is no shared file across
sources.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

ROOT = Path(__file__).parent.parent
STATE_DIR = ROOT / ".preston-check" / "state"
QUEUE_DIR = ROOT / ".preston-check" / "queue"
BUDGET_FILE = ROOT / ".preston-check" / "budget.json"

USER_AGENT = "preston-check-ingest/1.0 (+https://preston-check.com/)"
HTTP_TIMEOUT = 30


class CandidateRecord(TypedDict, total=False):
    """Normalised candidate-record schema. Every source's fetch() returns a
    list of these; the synthesizer consumes them uniformly."""

    source: str
    source_id: str
    fetched_at: str
    title: str
    description: str
    severity: str
    cwe: list[str]
    languages: list[str]
    frameworks: list[str]
    references: list[str]
    raw: dict[str, Any]
    confidence: float
    proactive: bool


def _ensure_dirs() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)


def load_state(source_id: str) -> dict[str, Any]:
    _ensure_dirs()
    path = STATE_DIR / f"{source_id}.json"
    if not path.is_file():
        return {
            "source_id": source_id,
            "last_run": None,
            "last_successful_fetch": None,
            "processed_ids": [],
            "stats": {"total_fetched": 0, "total_relevant": 0},
        }
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {
            "source_id": source_id,
            "last_run": None,
            "last_successful_fetch": None,
            "processed_ids": [],
            "stats": {"total_fetched": 0, "total_relevant": 0},
            "_recovered_from_corruption": True,
        }


def save_state(source_id: str, state: dict[str, Any]) -> None:
    _ensure_dirs()
    path = STATE_DIR / f"{source_id}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    os.replace(tmp, path)


def write_queue_batch(source_id: str, records: list[CandidateRecord]) -> Path:
    """Write a batch of candidate records to the queue. Filename is
    deterministic for reproducibility but timestamp-suffixed for ordering."""
    _ensure_dirs()
    if not records:
        empty_path = QUEUE_DIR / f"{source_id}-{int(time.time())}-empty.json"
        empty_path.write_text("[]")
        return empty_path
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = QUEUE_DIR / f"{source_id}-{ts}.json"
    path.write_text(json.dumps(records, indent=2, sort_keys=True))
    return path


def http_get_json(
    url: str,
    headers: dict[str, str] | None = None,
    retries: int = 2,
    timeout: int = HTTP_TIMEOUT,
) -> dict[str, Any] | None:
    """GET a URL expected to return JSON. Returns None on failure (caller
    decides whether to retry next cycle vs fail-loud)."""
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        h.update(headers)
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                return json.loads(data) if data else None
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(1 + attempt * 2)
                continue
        except json.JSONDecodeError as exc:
            last_err = exc
            break
        except Exception as exc:
            last_err = exc
            break
    print(f"[ingest_common] http_get_json failed for {url}: {last_err}", file=sys.stderr)
    return None


def http_get_text(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = HTTP_TIMEOUT,
) -> str | None:
    """GET a URL and return the body as text (e.g., for RSS feeds, mailing
    list archives, etc.)."""
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"[ingest_common] http_get_text failed for {url}: {exc}", file=sys.stderr)
        return None


def load_budget() -> dict[str, dict[str, float]]:
    """Load the per-source daily budget tracker."""
    _ensure_dirs()
    if not BUDGET_FILE.is_file():
        return {}
    try:
        return json.loads(BUDGET_FILE.read_text())
    except json.JSONDecodeError:
        return {}


def save_budget(budget: dict[str, dict[str, float]]) -> None:
    _ensure_dirs()
    tmp = BUDGET_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(budget, indent=2, sort_keys=True))
    os.replace(tmp, BUDGET_FILE)


def check_budget(source_id: str, daily_cap_usd: float | None) -> tuple[bool, float]:
    """Return (within_budget, current_spend) for the source's today bucket."""
    if daily_cap_usd is None:
        return True, 0.0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    budget = load_budget()
    bucket = budget.get(source_id, {})
    spend = bucket.get(today, 0.0)
    return spend < daily_cap_usd, spend


def record_spend(source_id: str, amount_usd: float) -> None:
    """Record an LLM/API spend against the source's daily bucket. Cleans up
    bucket entries older than 7 days."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    budget = load_budget()
    bucket = budget.setdefault(source_id, {})
    bucket[today] = round(bucket.get(today, 0.0) + amount_usd, 4)
    cutoff = (datetime.now(timezone.utc).timestamp() - 7 * 86400)
    keep = {}
    for date_key, value in bucket.items():
        try:
            ts = datetime.strptime(date_key, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
            if ts >= cutoff:
                keep[date_key] = value
        except ValueError:
            keep[date_key] = value
    budget[source_id] = keep
    save_budget(budget)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
