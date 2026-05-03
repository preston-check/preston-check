#!/usr/bin/env python3
"""
tools/sync-threat-intel.py

Threat-intelligence auto-ingestion pipeline. Runs daily, reads CVE feeds
and security advisories, identifies fintech-relevant patterns, and either
generates draft community-tier checks for maintainer review or augments
existing check metadata with newly-published CVE references.

This is the moat-building component that keeps the catalog updating
faster than competitors can manually maintain. After 6-12 months of
operation the catalog reflects threat intelligence that competing tools
have to chase to keep up with.

Sources:
  - NIST NVD CVE feed (https://nvd.nist.gov/feeds/json/cve/1.1/)
  - GitHub Security Advisories (gh api /advisories)
  - OSV.dev (https://osv.dev/list)

Output:
  - checks/community/proposed/{NUMBER}-{slug}.sh — draft checks for maintainer review
  - checks/{existing}.sh — appends new CVE references to existing check metadata
  - state.json — tracks last-processed CVE ID to avoid reprocessing

Usage:
    python3 tools/sync-threat-intel.py [--dry-run] [--max-new 10]
"""

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent.parent
CHECKS = ROOT / "checks"
PROPOSED = CHECKS / "community" / "proposed"
STATE_FILE = Path.home() / ".preston-check" / "threat-intel-state.json"

# CVE sources (free, no auth required for these endpoints)
NVD_FEED = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}"
OSV_LIST = "https://api.osv.dev/v1/query"

# Fintech-relevance keywords. A CVE matching any of these is a candidate
# for either generating a new check or augmenting an existing one.
FINTECH_KEYWORDS = [
    # Languages we cover
    "java", "kotlin", "typescript", "javascript", "node.js", "python",
    "golang", "rust", "solidity", "move", "ruby", "php", ".net", "csharp",
    # Frameworks / ecosystems we cover
    "spring", "fastapi", "django", "rails", "express", "next.js",
    "openzeppelin", "anchor framework", "fireblocks", "stripe", "plaid",
    # Technologies in fintech stacks
    "redis", "postgres", "mongodb", "kafka", "rabbitmq", "vault",
    # Crypto / DeFi
    "smart contract", "ethereum", "bitcoin", "solana", "evm", "defi",
    "wallet", "private key", "hardware wallet", "multisig",
    # Vulnerability classes we focus on
    "sql injection", "xxe", "deserialization", "ssrf", "rce",
    "authentication bypass", "authorization", "sensitive data exposure",
    "race condition", "timing attack", "supply chain",
]

# Severity mapping from CVSS to Preston-Check severity vocabulary
def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"last_run": None, "processed_cves": []}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def fetch_recent_cves(since: datetime) -> list:
    """Fetch CVEs from NVD published since the given datetime."""
    url = NVD_FEED.format(
        start=since.strftime("%Y-%m-%dT00:00:00.000"),
        end=datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00.000"),
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"NVD fetch failed: {e}", file=sys.stderr)
        return []


def is_fintech_relevant(cve: dict) -> bool:
    description = ""
    for desc in cve.get("cve", {}).get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "").lower()
            break
    if not description:
        return False
    return any(kw in description for kw in FINTECH_KEYWORDS)


def next_proposed_number() -> int:
    """Find the next available P-XXX number in checks/community/proposed/."""
    PROPOSED.mkdir(parents=True, exist_ok=True)
    used = set()
    for f in PROPOSED.glob("*.sh"):
        m = re.match(r"^(\d+)-", f.name)
        if m:
            used.add(int(m.group(1)))
    n = 600
    while n in used:
        n += 1
    return n


def slugify(text: str, max_len: int = 40) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
    return s[:max_len].rstrip("-")


def generate_check_from_cve(cve: dict, number: int) -> Optional[str]:
    """Render a draft check script. Returns the file content, or None if skipped."""
    cve_id = cve.get("cve", {}).get("id", "")
    if not cve_id:
        return None

    description = ""
    for desc in cve.get("cve", {}).get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    metrics = cve.get("cve", {}).get("metrics", {})
    score = 5.0
    for variant in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if variant in metrics and metrics[variant]:
            score = metrics[variant][0].get("cvssData", {}).get("baseScore", 5.0)
            break
    severity = cvss_to_severity(score)

    name = f"{cve_id} — {description.split('.')[0][:60]}"
    slug = slugify(f"{cve_id}-{description[:30]}")
    filename = f"{number}-{slug}.sh"

    # Heuristic: extract a likely grep pattern from the description.
    # In production, this would call the LLM (lib/ai_analyze.sh) to
    # generate a real detection pattern. For now, we emit a placeholder
    # that explicitly requires maintainer authoring.
    content = f"""#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: P-{number}
name: {name[:80]}
description: Auto-drafted from {cve_id} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')}). Description: {description[:200]}
category: code-scan
severity: {severity}
languages: any
min_tier: free
runtime_class: static-grep
evidence_required: false
version: 0.1.0
added_in: 1.6.0
author_name: Preston-Check Threat-Intel Pipeline
author_github: prestoncheck-bot
frameworks: CVE:{cve_id}
cwe: {extract_cwe(cve)}
false_positive_rate: high
performance_class: fast
origin: Auto-generated from NIST NVD {cve_id}; requires maintainer review and pattern refinement before promotion to checks/community/accepted/
PRESTON_META

echo "P-{number}: Draft check from {cve_id}"

# AUTO-DRAFTED — REQUIRES MAINTAINER REVIEW
# CVE description: {description[:300]}
#
# Pattern needs to be authored. Replace this block with a real grep pattern
# that detects the vulnerable usage. Then move from checks/community/proposed/
# to checks/community/accepted/ via the normal PR flow.

SRC="${{SOURCE_DIR:-.}}"
record "SKIP" "P-{number} {cve_id} draft" "Auto-generated draft; requires maintainer pattern authoring"
"""
    return content


def extract_cwe(cve: dict) -> str:
    weaknesses = cve.get("cve", {}).get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                cwes.append(v[4:])
    return ", ".join(cwes) if cwes else ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-new", type=int, default=10, help="Max new checks per run")
    parser.add_argument("--days-back", type=int, default=7)
    args = parser.parse_args()

    state = load_state()
    since = datetime.now(timezone.utc) - timedelta(days=args.days_back)
    print(f"Fetching CVEs since {since.strftime('%Y-%m-%d')}...")

    cves = fetch_recent_cves(since)
    print(f"NVD returned {len(cves)} CVEs in window")

    relevant = [c for c in cves if is_fintech_relevant(c)]
    print(f"Fintech-relevant: {len(relevant)}")

    new_drafts = 0
    next_n = next_proposed_number()
    for cve in relevant:
        cve_id = cve.get("cve", {}).get("id", "")
        if cve_id in state["processed_cves"]:
            continue
        if new_drafts >= args.max_new:
            break

        content = generate_check_from_cve(cve, next_n)
        if not content:
            continue

        slug = slugify(f"{cve_id}-{cve.get('cve', {}).get('descriptions', [{}])[0].get('value', '')[:30]}")
        filename = f"{next_n}-{slug}.sh"
        target = PROPOSED / filename

        if args.dry_run:
            print(f"[DRY] would write {target}")
        else:
            PROPOSED.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            target.chmod(0o755)
            print(f"Drafted {target.name} ({cve_id})")

        state["processed_cves"].append(cve_id)
        next_n += 1
        new_drafts += 1

    state["last_run"] = datetime.now(timezone.utc).isoformat()
    if not args.dry_run:
        save_state(state)

    print()
    print(f"New drafts written:        {new_drafts}")
    print(f"Total CVEs in state file:  {len(state['processed_cves'])}")
    print(f"Next available number:     P-{next_n}")
    print()
    print("Next steps:")
    print("  1. Review drafts in checks/community/proposed/")
    print("  2. Author actual grep patterns (or use lib/ai_analyze.sh to generate)")
    print("  3. Move accepted ones to checks/community/accepted/ via PR")


if __name__ == "__main__":
    main()
