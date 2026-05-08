#!/usr/bin/env python3
"""tools/ingest_sources.py

All ingester source modules in one file. Each source exposes:
  - ID (str)
  - POLL_SECONDS (int)
  - BUDGET_USD_DAILY (float | None)
  - PROACTIVE (bool) — whether this is a tier-1 proactive source
  - fetch(state) -> list[CandidateRecord], dict (new state)

The unified runner in tools/ingest_runner.py dispatches to a source by
ID. Adding a new source = adding a new function here and registering
it in SOURCES at the bottom.

Reactive sources (post-disclosure):
  - kev: CISA Known Exploited Vulnerabilities (highest signal)
  - ghsa: GitHub Security Advisories
  - nvd: NIST National Vulnerability Database
  - osv: OSV.dev (multi-ecosystem)

Proactive tier-1 sources (pre-disclosure or early disclosure):
  - github_trending: GitHub repos with exploit/PoC topics
  - abuse_ch: ThreatFox IOC feed
  - reddit: security-related subreddits
  - mastodon: infosec Mastodon hashtag feed
  - mailing_list: oss-security archive
  - conference_zdi: Trend Micro Zero Day Initiative advisories

Stub for tier-3 (commercial threat-intel partner feed):
  - partner_feed: interface stub; activated when operator picks a vendor
"""

from __future__ import annotations

import html
import re
import sys
from typing import Any

from ingest_common import (
    CandidateRecord,
    http_get_json,
    http_get_text,
    now_iso,
)


_FINTECH_KEYWORDS = (
    "java",
    "kotlin",
    "typescript",
    "javascript",
    "node",
    "node.js",
    "python",
    "golang",
    "go ",
    "rust",
    "solidity",
    "move",
    "ruby",
    "php",
    ".net",
    "csharp",
    "c#",
    "spring",
    "fastapi",
    "django",
    "rails",
    "express",
    "next.js",
    "openzeppelin",
    "anchor",
    "fireblocks",
    "stripe",
    "plaid",
    "redis",
    "postgres",
    "mongodb",
    "kafka",
    "rabbitmq",
    "vault",
    "smart contract",
    "ethereum",
    "bitcoin",
    "solana",
    "evm",
    "defi",
    "wallet",
    "private key",
    "multisig",
    "sql injection",
    "xxe",
    "deserialization",
    "ssrf",
    "rce",
    "authentication bypass",
    "authorization",
    "sensitive data exposure",
    "race condition",
    "timing attack",
    "supply chain",
    "fintech",
    "banking",
    "payment",
    "kyc",
    "aml",
)


def _is_fintech_relevant(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    return any(kw in lower for kw in _FINTECH_KEYWORDS)


def _cwes_from_str(s: str) -> list[str]:
    return list(set(re.findall(r"CWE-\d+", s or "")))


def _cap_processed(state: dict, max_keep: int = 5000) -> None:
    proc = state.get("processed_ids", [])
    if len(proc) > max_keep:
        state["processed_ids"] = proc[-max_keep:]


def _kev_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = http_get_json(url)
    if not data:
        return [], state
    state["last_run"] = now_iso()
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    for v in data.get("vulnerabilities", []):
        cve_id = v.get("cveID")
        if not cve_id or cve_id in seen:
            continue
        desc = v.get("shortDescription", "") or v.get("vulnerabilityName", "")
        rec: CandidateRecord = {
            "source": "kev",
            "source_id": cve_id,
            "fetched_at": now_iso(),
            "title": v.get("vulnerabilityName") or cve_id,
            "description": desc,
            "severity": "critical",
            "cwe": _cwes_from_str(desc),
            "languages": [],
            "frameworks": [v.get("vendorProject", ""), v.get("product", "")],
            "references": [v.get("notes", "")] if v.get("notes") else [],
            "raw": v,
            "confidence": 0.95,
            "proactive": False,
        }
        records.append(rec)
        seen.add(cve_id)
        state.setdefault("processed_ids", []).append(cve_id)
    state["last_successful_fetch"] = now_iso()
    state.setdefault("stats", {}).update(
        {
            "total_fetched": state.get("stats", {}).get("total_fetched", 0)
            + len(data.get("vulnerabilities", [])),
            "total_relevant": state.get("stats", {}).get("total_relevant", 0) + len(records),
        }
    )
    _cap_processed(state)
    return records, state


def _ghsa_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    url = "https://api.github.com/advisories?per_page=100&sort=published"
    data = http_get_json(url, headers={"Accept": "application/vnd.github+json"})
    if not data:
        return [], state
    state["last_run"] = now_iso()
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    items = data if isinstance(data, list) else data.get("items", [])
    for adv in items:
        adv_id = adv.get("ghsa_id")
        if not adv_id or adv_id in seen:
            continue
        desc = adv.get("description", "") or adv.get("summary", "")
        if not _is_fintech_relevant(desc + " " + adv.get("summary", "")):
            seen.add(adv_id)
            state.setdefault("processed_ids", []).append(adv_id)
            continue
        sev = (adv.get("severity") or "medium").lower()
        cwes_list = adv.get("cwes", []) or []
        vulns_list = adv.get("vulnerabilities", []) or []
        refs_list = adv.get("references", []) or []
        rec: CandidateRecord = {
            "source": "ghsa",
            "source_id": adv_id,
            "fetched_at": now_iso(),
            "title": adv.get("summary") or adv_id,
            "description": desc,
            "severity": sev,
            "cwe": [w.get("cwe_id", "") for w in cwes_list if isinstance(w, dict)],
            "languages": [],
            "frameworks": [
                v.get("package", {}).get("ecosystem", "")
                for v in vulns_list
                if isinstance(v, dict)
            ],
            "references": [
                r if isinstance(r, str) else r.get("url", "") for r in refs_list
            ],
            "raw": adv,
            "confidence": 0.85,
            "proactive": False,
        }
        records.append(rec)
        seen.add(adv_id)
        state.setdefault("processed_ids", []).append(adv_id)
    state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _nvd_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    from datetime import datetime, timedelta, timezone

    since = datetime.now(timezone.utc) - timedelta(days=2)
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
        f"pubStartDate={since.strftime('%Y-%m-%dT00:00:00.000')}&"
        f"pubEndDate={datetime.now(timezone.utc).strftime('%Y-%m-%dT00:00:00.000')}"
    )
    data = http_get_json(url)
    if not data:
        return [], state
    state["last_run"] = now_iso()
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id or cve_id in seen:
            continue
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not _is_fintech_relevant(desc):
            seen.add(cve_id)
            state.setdefault("processed_ids", []).append(cve_id)
            continue
        score = 5.0
        for variant in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(variant, [])
            if metrics:
                score = metrics[0].get("cvssData", {}).get("baseScore", 5.0)
                break
        sev = (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
        )
        cwes: list[str] = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])
        rec: CandidateRecord = {
            "source": "nvd",
            "source_id": cve_id,
            "fetched_at": now_iso(),
            "title": cve_id,
            "description": desc,
            "severity": sev,
            "cwe": list(set(cwes)),
            "languages": [],
            "frameworks": [],
            "references": [r.get("url", "") for r in cve.get("references", [])],
            "raw": cve,
            "confidence": 0.80,
            "proactive": False,
        }
        records.append(rec)
        seen.add(cve_id)
        state.setdefault("processed_ids", []).append(cve_id)
    state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _osv_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    """OSV.dev's /v1/query endpoint requires POST with a specific package.
    There is no list-recent endpoint; instead we query a curated list of
    fintech-relevant packages on each run and pull their latest vulns. The
    package list is biased toward frameworks Preston-Check actually targets;
    expand it to broaden coverage."""
    import json as _json
    import urllib.request as _ur

    fintech_packages = [
        ("Maven", "org.springframework:spring-core"),
        ("Maven", "org.springframework.boot:spring-boot"),
        ("Maven", "org.springframework.security:spring-security-core"),
        ("Maven", "com.fasterxml.jackson.core:jackson-databind"),
        ("npm", "express"),
        ("npm", "next"),
        ("npm", "react"),
        ("npm", "stripe"),
        ("npm", "ethers"),
        ("npm", "web3"),
        ("PyPI", "django"),
        ("PyPI", "fastapi"),
        ("PyPI", "stripe"),
        ("PyPI", "cryptography"),
        ("Go", "github.com/gin-gonic/gin"),
        ("Go", "github.com/gorilla/mux"),
        ("RubyGems", "rails"),
        ("crates.io", "openssl"),
        ("crates.io", "ring"),
    ]

    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    state["last_run"] = now_iso()
    any_success = False

    for ecosystem, package in fintech_packages:
        body = _json.dumps({"package": {"ecosystem": ecosystem, "name": package}}).encode("utf-8")
        req = _ur.Request(
            "https://api.osv.dev/v1/query",
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "preston-check-ingest/1.0",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with _ur.urlopen(req, timeout=30) as resp:
                data = _json.loads(resp.read())
            any_success = True
        except Exception as exc:
            print(
                f"[ingest_sources] osv query failed for {ecosystem}/{package}: {exc}",
                file=sys.stderr,
            )
            continue

        for vuln in data.get("vulns", [])[:25]:
            vid = vuln.get("id")
            if not vid or vid in seen:
                continue
            summary = vuln.get("summary", "") or (vuln.get("details", "") or "")[:200]
            if not _is_fintech_relevant(summary + " " + (vuln.get("details", "") or "")):
                seen.add(vid)
                state.setdefault("processed_ids", []).append(vid)
                continue
            refs_list = vuln.get("references", []) or []
            rec: CandidateRecord = {
                "source": "osv",
                "source_id": vid,
                "fetched_at": now_iso(),
                "title": summary or vid,
                "description": vuln.get("details", "") or summary,
                "severity": "medium",
                "cwe": [],
                "languages": [],
                "frameworks": [f"{ecosystem}:{package}"],
                "references": [
                    r if isinstance(r, str) else r.get("url", "") for r in refs_list
                ],
                "raw": vuln,
                "confidence": 0.75,
                "proactive": False,
            }
            records.append(rec)
            seen.add(vid)
            state.setdefault("processed_ids", []).append(vid)

    if any_success:
        state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _github_trending_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    import urllib.parse as _up

    queries = [
        "topic:exploit topic:poc",
        "topic:vulnerability topic:rce",
        "CVE in:name",
        "0day in:description",
    ]
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    state["last_run"] = now_iso()
    any_success = False
    for q in queries:
        encoded_q = _up.quote(q)
        url = f"https://api.github.com/search/repositories?q={encoded_q}&sort=updated&per_page=30"
        data = http_get_json(url, headers={"Accept": "application/vnd.github+json"})
        if not data:
            continue
        any_success = True
        for item in data.get("items", [])[:30]:
            repo_id = f"github:{item.get('full_name')}"
            if repo_id in seen:
                continue
            desc = item.get("description") or ""
            if not _is_fintech_relevant(desc + " " + (item.get("name") or "")):
                seen.add(repo_id)
                state.setdefault("processed_ids", []).append(repo_id)
                continue
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", (item.get("name") or "") + " " + desc)
            rec: CandidateRecord = {
                "source": "github_trending",
                "source_id": repo_id,
                "fetched_at": now_iso(),
                "title": item.get("name") or repo_id,
                "description": desc,
                "severity": "high",
                "cwe": _cwes_from_str(desc),
                "languages": [item.get("language") or ""],
                "frameworks": item.get("topics", []) or [],
                "references": [item.get("html_url", "")],
                "raw": {
                    "stars": item.get("stargazers_count"),
                    "topics": item.get("topics"),
                    "linked_cve": cve_match.group(0) if cve_match else None,
                },
                "confidence": 0.55,
                "proactive": True,
            }
            records.append(rec)
            seen.add(repo_id)
            state.setdefault("processed_ids", []).append(repo_id)
    if any_success:
        state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _abuse_ch_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    url = "https://threatfox.abuse.ch/export/json/recent/"
    data = http_get_json(url)
    if not data:
        return [], state
    state["last_run"] = now_iso()
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    items: list[Any] = []
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                items.extend(v)
    elif isinstance(data, list):
        items = data
    for entry in items[:200]:
        if not isinstance(entry, dict):
            continue
        eid = f"threatfox:{entry.get('id', entry.get('ioc_value', ''))}"
        if eid in seen:
            continue
        desc = entry.get("threat_type_desc") or entry.get("malware_printable", "") or ""
        rec: CandidateRecord = {
            "source": "abuse_ch",
            "source_id": eid,
            "fetched_at": now_iso(),
            "title": f"ThreatFox: {entry.get('malware_printable', 'unknown')}",
            "description": desc,
            "severity": "high",
            "cwe": [],
            "languages": [],
            "frameworks": [entry.get("malware_alias", "") or ""],
            "references": [entry.get("reference", "")] if entry.get("reference") else [],
            "raw": entry,
            "confidence": 0.50,
            "proactive": True,
        }
        records.append(rec)
        seen.add(eid)
        state.setdefault("processed_ids", []).append(eid)
    state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _reddit_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    """Reddit requires OAuth for cloud-IP requests as of 2024. To activate
    this ingester, register a Reddit app at https://www.reddit.com/prefs/apps,
    set REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET as repo secrets, and
    extend this function to do the OAuth flow. Until then, return empty.
    """
    import os as _os

    state["last_run"] = now_iso()
    if not _os.environ.get("REDDIT_CLIENT_ID") or not _os.environ.get("REDDIT_CLIENT_SECRET"):
        state["status"] = "skipped — REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET not configured"
        return [], state

    subs = ["netsec", "AskNetsec", "redteamsec", "Malware"]
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    any_success = False
    for sub in subs:
        url = f"https://www.reddit.com/r/{sub}/new.json?limit=50"
        data = http_get_json(url)
        if not data:
            continue
        any_success = True
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            pid = f"reddit:{post.get('id')}"
            if pid in seen:
                continue
            title = post.get("title", "")
            body = post.get("selftext", "")
            if not _is_fintech_relevant(title + " " + body):
                seen.add(pid)
                state.setdefault("processed_ids", []).append(pid)
                continue
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", title + " " + body)
            rec: CandidateRecord = {
                "source": "reddit",
                "source_id": pid,
                "fetched_at": now_iso(),
                "title": title,
                "description": body[:1500],
                "severity": "medium",
                "cwe": _cwes_from_str(title + " " + body),
                "languages": [],
                "frameworks": [sub],
                "references": [f"https://reddit.com{post.get('permalink', '')}"],
                "raw": {
                    "subreddit": sub,
                    "score": post.get("score"),
                    "num_comments": post.get("num_comments"),
                    "linked_cve": cve_match.group(0) if cve_match else None,
                },
                "confidence": 0.40,
                "proactive": True,
            }
            records.append(rec)
            seen.add(pid)
            state.setdefault("processed_ids", []).append(pid)
    if any_success:
        state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _mastodon_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    """infosec.exchange's tag-timeline endpoint requires authentication as of
    2024. To activate, create a Mastodon application at
    https://infosec.exchange/settings/applications and set MASTODON_TOKEN as a
    repo secret. Without the token, we skip rather than fail."""
    import os as _os

    state["last_run"] = now_iso()
    token = _os.environ.get("MASTODON_TOKEN", "")
    if not token:
        state["status"] = "skipped — MASTODON_TOKEN not configured"
        return [], state

    url = "https://infosec.exchange/api/v1/timelines/tag/infosec?limit=40"
    data = http_get_json(url, headers={"Authorization": f"Bearer {token}"})
    if not data:
        return [], state
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    for status in data if isinstance(data, list) else []:
        sid = f"mastodon:{status.get('id')}"
        if sid in seen:
            continue
        content = re.sub(r"<[^>]+>", " ", status.get("content", ""))
        content = html.unescape(content)
        if not _is_fintech_relevant(content):
            seen.add(sid)
            state.setdefault("processed_ids", []).append(sid)
            continue
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", content)
        rec: CandidateRecord = {
            "source": "mastodon",
            "source_id": sid,
            "fetched_at": now_iso(),
            "title": (content[:120] + "...") if len(content) > 120 else content,
            "description": content[:1500],
            "severity": "medium",
            "cwe": _cwes_from_str(content),
            "languages": [],
            "frameworks": [t.get("name", "") for t in status.get("tags", [])],
            "references": [status.get("url", "")] if status.get("url") else [],
            "raw": {
                "reblogs": status.get("reblogs_count"),
                "favourites": status.get("favourites_count"),
                "linked_cve": cve_match.group(0) if cve_match else None,
            },
            "confidence": 0.45,
            "proactive": True,
        }
        records.append(rec)
        seen.add(sid)
        state.setdefault("processed_ids", []).append(sid)
    state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _mailing_list_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    url = "https://www.openwall.com/lists/oss-security/"
    body = http_get_text(url)
    if not body:
        return [], state
    state["last_run"] = now_iso()
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    pattern = re.compile(
        r'<a href="(\d{4}/\d{2}/\d{2}/\d+)">([^<]+)</a>',
        re.MULTILINE,
    )
    for match in pattern.finditer(body):
        link = match.group(1)
        title = html.unescape(match.group(2))
        mid = f"oss-security:{link}"
        if mid in seen:
            continue
        if not _is_fintech_relevant(title):
            seen.add(mid)
            state.setdefault("processed_ids", []).append(mid)
            continue
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", title)
        rec: CandidateRecord = {
            "source": "mailing_list",
            "source_id": mid,
            "fetched_at": now_iso(),
            "title": title,
            "description": title,
            "severity": "medium",
            "cwe": [],
            "languages": [],
            "frameworks": ["oss-security"],
            "references": [f"https://www.openwall.com/lists/oss-security/{link}"],
            "raw": {"link": link, "linked_cve": cve_match.group(0) if cve_match else None},
            "confidence": 0.65,
            "proactive": True,
        }
        records.append(rec)
        seen.add(mid)
        state.setdefault("processed_ids", []).append(mid)
    state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _conference_zdi_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    url = "https://www.zerodayinitiative.com/rss/published/"
    body = http_get_text(url)
    if not body:
        return [], state
    state["last_run"] = now_iso()
    records: list[CandidateRecord] = []
    seen = set(state.get("processed_ids", []))
    item_pattern = re.compile(
        r"<item>(.*?)</item>",
        re.DOTALL | re.IGNORECASE,
    )
    title_pattern = re.compile(r"<title>(.*?)</title>", re.DOTALL | re.IGNORECASE)
    link_pattern = re.compile(r"<link>(.*?)</link>", re.DOTALL | re.IGNORECASE)
    desc_pattern = re.compile(
        r"<description>(.*?)</description>",
        re.DOTALL | re.IGNORECASE,
    )
    for item_match in item_pattern.finditer(body):
        item_xml = item_match.group(1)
        tm = title_pattern.search(item_xml)
        lm = link_pattern.search(item_xml)
        dm = desc_pattern.search(item_xml)
        title = html.unescape((tm.group(1) if tm else "").strip())
        link = (lm.group(1) if lm else "").strip()
        desc = html.unescape(re.sub(r"<[^>]+>", " ", dm.group(1) if dm else ""))
        if not link:
            continue
        rid = f"zdi:{link}"
        if rid in seen:
            continue
        if not _is_fintech_relevant(title + " " + desc):
            seen.add(rid)
            state.setdefault("processed_ids", []).append(rid)
            continue
        rec: CandidateRecord = {
            "source": "conference_zdi",
            "source_id": rid,
            "fetched_at": now_iso(),
            "title": title,
            "description": desc[:1500],
            "severity": "high",
            "cwe": _cwes_from_str(desc),
            "languages": [],
            "frameworks": ["zdi"],
            "references": [link],
            "raw": {"link": link},
            "confidence": 0.70,
            "proactive": True,
        }
        records.append(rec)
        seen.add(rid)
        state.setdefault("processed_ids", []).append(rid)
    state["last_successful_fetch"] = now_iso()
    _cap_processed(state)
    return records, state


def _partner_feed_fetch(state: dict) -> tuple[list[CandidateRecord], dict]:
    """Stub for tier-3 commercial partner feed (Flashpoint, Recorded
    Future, Intel 471, KELA, Cybersixgill, AlienVault OTX, etc.).

    When the operator picks a vendor, this function gets replaced with
    a real implementation. The interface stays stable — caller doesn't
    care which vendor produced the records as long as the schema
    matches.
    """
    state["last_run"] = now_iso()
    state["partner_status"] = "no vendor configured; tier-3 stub returns empty"
    return [], state


SOURCES: dict[str, dict[str, Any]] = {
    "kev": {
        "fetch": _kev_fetch,
        "poll_seconds": 900,
        "budget_usd_daily": None,
        "proactive": False,
        "description": "CISA Known Exploited Vulnerabilities",
    },
    "ghsa": {
        "fetch": _ghsa_fetch,
        "poll_seconds": 3600,
        "budget_usd_daily": 50.0,
        "proactive": False,
        "description": "GitHub Security Advisories",
    },
    "nvd": {
        "fetch": _nvd_fetch,
        "poll_seconds": 21600,
        "budget_usd_daily": 30.0,
        "proactive": False,
        "description": "NIST National Vulnerability Database",
    },
    "osv": {
        "fetch": _osv_fetch,
        "poll_seconds": 21600,
        "budget_usd_daily": 30.0,
        "proactive": False,
        "description": "OSV.dev multi-ecosystem vulnerability database",
    },
    "github_trending": {
        "fetch": _github_trending_fetch,
        "poll_seconds": 3600,
        "budget_usd_daily": 20.0,
        "proactive": True,
        "description": "GitHub trending repos with exploit/PoC topics",
    },
    "abuse_ch": {
        "fetch": _abuse_ch_fetch,
        "poll_seconds": 3600,
        "budget_usd_daily": 10.0,
        "proactive": True,
        "description": "abuse.ch ThreatFox IOC feed",
    },
    "reddit": {
        "fetch": _reddit_fetch,
        "poll_seconds": 3600,
        "budget_usd_daily": 10.0,
        "proactive": True,
        "description": "Security-related subreddits",
    },
    "mastodon": {
        "fetch": _mastodon_fetch,
        "poll_seconds": 3600,
        "budget_usd_daily": 10.0,
        "proactive": True,
        "description": "infosec.exchange Mastodon timeline",
    },
    "mailing_list": {
        "fetch": _mailing_list_fetch,
        "poll_seconds": 7200,
        "budget_usd_daily": 10.0,
        "proactive": True,
        "description": "oss-security mailing list archive",
    },
    "conference_zdi": {
        "fetch": _conference_zdi_fetch,
        "poll_seconds": 21600,
        "budget_usd_daily": 5.0,
        "proactive": True,
        "description": "Zero Day Initiative published advisories",
    },
    "partner_feed": {
        "fetch": _partner_feed_fetch,
        "poll_seconds": 3600,
        "budget_usd_daily": None,
        "proactive": True,
        "description": "Commercial partner threat-intel feed (stub; activate when vendor selected)",
    },
}
