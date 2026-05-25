#!/usr/bin/env python3
"""tools/correlator.py

Weak-signal correlator. Reads queued candidate records from
.preston-check/queue/ and produces correlated, prioritised candidates
for synthesis.

Why this exists: tier-1 proactive sources (Reddit, Mastodon, GitHub
trending, abuse.ch, oss-security mailing list, ZDI) individually have
high noise. A single Reddit post mentioning a CVE is weak signal. The
same CVE mentioned across Reddit, Mastodon, GitHub repo, and ZDI
within a 48-hour window is high signal — the correlator promotes it.

Reactive sources (KEV, GHSA, NVD, OSV) skip correlation; they're
already-validated CVE assignments and go straight to the synthesis
queue.

Output: a single correlated-candidates.json file that the synthesizer
consumes, where each entry carries:
  - merged_sources: which sources contributed
  - composite_confidence: max(individual confidences) plus boosts
    for cross-source agreement
  - canonical_id: prefers CVE id when present, else best source_id
  - raw: list of original records
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
QUEUE_DIR = ROOT / ".preston-check" / "queue"
OUT_FILE = ROOT / ".preston-check" / "correlated.json"


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _extract_cve(record: dict) -> str | None:
    text = (record.get("title") or "") + " " + (record.get("description") or "")
    raw = record.get("raw") or {}
    if isinstance(raw, dict):
        for v in raw.values():
            if isinstance(v, str):
                text += " " + v
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        text += " " + item
    m = _CVE_RE.search(text)
    return m.group(0) if m else None


def _candidate_key(record: dict) -> tuple[str, str]:
    cve = _extract_cve(record)
    if cve:
        return ("cve", cve)
    src = record.get("source", "unknown")
    sid = record.get("source_id", "")
    return ("sid", f"{src}:{sid}")


def correlate(queue_dir: Path = QUEUE_DIR) -> list[dict]:
    """Read all queue files, group by canonical key, emit correlated records."""
    if not queue_dir.is_dir():
        return []

    by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
    files = sorted(queue_dir.glob("*.json"))
    for qf in files:
        try:
            data = json.loads(qf.read_text())
        except json.JSONDecodeError:
            continue
        if not isinstance(data, list):
            continue
        for record in data:
            if not isinstance(record, dict):
                continue
            by_key[_candidate_key(record)].append(record)

    correlated: list[dict] = []
    for key_kind, key_value in sorted(by_key.keys()):
        records = by_key[(key_kind, key_value)]
        if not records:
            continue
        sources = sorted({r.get("source", "unknown") for r in records})
        proactive_only = all(r.get("proactive", False) for r in records)
        reactive_present = any(not r.get("proactive", False) for r in records)

        if proactive_only and len(sources) < 2:
            continue

        max_conf = max((r.get("confidence", 0.5) for r in records), default=0.5)
        cross_source_boost = min(0.15, 0.05 * (len(sources) - 1))
        reactive_boost = 0.10 if reactive_present else 0.0
        composite = round(min(0.99, max_conf + cross_source_boost + reactive_boost), 4)

        best_record = max(records, key=lambda r: r.get("confidence", 0.0))

        correlated.append(
            {
                "canonical_id": key_value if key_kind == "cve" else best_record.get("source_id", key_value),
                "key_kind": key_kind,
                "merged_sources": sources,
                "source_count": len(sources),
                "composite_confidence": composite,
                "title": best_record.get("title", ""),
                "description": best_record.get("description", ""),
                "severity": best_record.get("severity", "medium"),
                "cwe": sorted(set(c for r in records for c in r.get("cwe", []) if c)),
                "languages": sorted(set(l for r in records for l in r.get("languages", []) if l)),
                "frameworks": sorted(set(f for r in records for f in r.get("frameworks", []) if f)),
                "references": sorted(set(ref for r in records for ref in r.get("references", []) if ref)),
                "first_seen": min((r.get("fetched_at", "") for r in records), default=""),
                "last_seen": max((r.get("fetched_at", "") for r in records), default=""),
                "proactive_only": proactive_only,
                "raw_records_count": len(records),
            }
        )

    correlated.sort(key=lambda x: x["composite_confidence"], reverse=True)
    return correlated


def main() -> int:
    parser = argparse.ArgumentParser(description="Correlate queued candidate records by canonical key.")
    parser.add_argument("--out", type=Path, default=OUT_FILE)
    parser.add_argument("--queue-dir", type=Path, default=QUEUE_DIR)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    correlated = correlate(args.queue_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {
                "correlated_at": datetime.now(timezone.utc).isoformat(),
                "candidate_count": len(correlated),
                "candidates": correlated,
            },
            indent=2,
            sort_keys=True,
        )
    )

    if args.json:
        print(json.dumps({"count": len(correlated), "out": str(args.out)}, indent=2))
    else:
        print(f"Correlated {len(correlated)} candidates -> {args.out}")
        if correlated:
            top = correlated[:5]
            print(f"  top-5 by composite confidence:")
            for c in top:
                print(
                    f"    {c['canonical_id']:<30} conf={c['composite_confidence']:<5} sources={','.join(c['merged_sources'])}"
                )

    return 0


if __name__ == "__main__":
    sys.exit(main())
