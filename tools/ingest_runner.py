#!/usr/bin/env python3
"""tools/ingest_runner.py

Unified ingester runner. Dispatches to a named source from
tools/ingest_sources.py, applies budget gating, persists state and
queue output, returns a summary.

Usage:
    python3 tools/ingest_runner.py --source kev
    python3 tools/ingest_runner.py --source ghsa --json
    python3 tools/ingest_runner.py --list

Each source's GitHub Actions workflow invokes this with --source <id>
on the source's own cadence. The workflow is identical across sources
except for the cron schedule and the source ID, which is what makes
adding new sources cheap.
"""

from __future__ import annotations

import argparse
import json
import sys

from ingest_common import (
    check_budget,
    load_state,
    save_state,
    write_queue_batch,
)
from ingest_sources import SOURCES


def run_source(source_id: str, dry_run: bool = False) -> dict:
    if source_id not in SOURCES:
        return {"ok": False, "reason": f"unknown source: {source_id}", "available": list(SOURCES.keys())}
    cfg = SOURCES[source_id]
    within_budget, current_spend = check_budget(source_id, cfg["budget_usd_daily"])
    if not within_budget:
        return {
            "ok": False,
            "reason": "daily budget exhausted",
            "source_id": source_id,
            "current_spend": current_spend,
            "cap": cfg["budget_usd_daily"],
        }

    state = load_state(source_id)
    fetch = cfg["fetch"]
    records, new_state = fetch(state)

    if not dry_run:
        save_state(source_id, new_state)
        queue_path = write_queue_batch(source_id, records)
    else:
        queue_path = None

    return {
        "ok": True,
        "source_id": source_id,
        "proactive": cfg["proactive"],
        "records_count": len(records),
        "queue_path": str(queue_path) if queue_path else None,
        "last_run": new_state.get("last_run"),
        "last_successful_fetch": new_state.get("last_successful_fetch"),
        "stats": new_state.get("stats", {}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a threat-intel ingester source.")
    parser.add_argument("--source", help="Source ID (run --list to see available)")
    parser.add_argument("--list", action="store_true", help="List available sources")
    parser.add_argument("--dry-run", action="store_true", help="Fetch but don't write state or queue")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human output")
    args = parser.parse_args()

    if args.list:
        if args.json:
            print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "fetch"} for k, v in SOURCES.items()}, indent=2))
        else:
            print(f"{'ID':<20} {'PROACTIVE':<12} {'POLL (s)':<10} {'BUDGET':<10} DESCRIPTION")
            print("-" * 100)
            for sid, cfg in SOURCES.items():
                budget = f"${cfg['budget_usd_daily']:.0f}/d" if cfg["budget_usd_daily"] else "uncapped"
                print(
                    f"{sid:<20} {'yes' if cfg['proactive'] else 'no':<12} {cfg['poll_seconds']:<10} {budget:<10} {cfg['description']}"
                )
        return 0

    if not args.source:
        parser.error("--source is required (or use --list)")

    result = run_source(args.source, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if not result["ok"]:
            print(f"FAIL  {result.get('source_id', args.source)}: {result['reason']}", file=sys.stderr)
            return 1
        print(f"OK    {result['source_id']}: {result['records_count']} new candidate records")
        if result["queue_path"]:
            print(f"      queue: {result['queue_path']}")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
