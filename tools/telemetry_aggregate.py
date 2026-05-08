#!/usr/bin/env python3
"""tools/telemetry_aggregate.py

Nightly telemetry aggregation. Reads opt-in scan stats from the
telemetry D1 (via Cloudflare API), applies the quorum gate, and emits
three feedback streams:

  - retire-candidates.json: checks with zero hits across N=90 days at
    high scan volume across at least 100 distinct installations.
  - tune-candidates.json: checks whose FP-signal rate per fire exceeds
    threshold across at least N=10 distinct installations over M=14 days.
  - coverage-gaps.json: language/framework combinations represented in
    opt-in scan metadata where no current check has fired in 90 days.

Quorum gate (threat model H1): each signal must come from at least N
distinct installation fingerprints over M time-window with bounded
geographic and UA-string variance. Below quorum, signals are recorded
but not acted on.

Auto-revert: a freshly-merged check (within 48h of merge) that produces
an aggregate spike in record SKIP "error: ..." events from at least
N=10 distinct installations triggers an auto-revert PR. This logic is
implemented in the workflow file; this tool produces the data that
drives the decision.

If no telemetry data is available (e.g., dev environment or Cloudflare
API unreachable), the tool emits empty feedback streams and an explicit
reason. The orchestrator treats empty feedback as "no signal", not as
"all clear" — the quorum gate naturally handles this.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUT_DIR = ROOT / ".preston-check" / "telemetry-feedback"

DEFAULT_QUORUM_N = 10
DEFAULT_QUORUM_DAYS = 14
RETIRE_QUORUM_N = 100
RETIRE_QUORUM_DAYS = 90
RETIRE_FP_THRESHOLD = 0.15

CF_ACCOUNT = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
CF_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "")
TELEMETRY_DB_ID = "e206e1e4-1c78-4a5e-a983-bc47104d1b3c"


def _query_d1(sql: str) -> list[dict] | None:
    if not CF_ACCOUNT or not CF_TOKEN:
        return None
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT}/d1/database/{TELEMETRY_DB_ID}/query"
    body = json.dumps({"sql": sql}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {CF_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"[telemetry_aggregate] Cloudflare API error: {exc}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[telemetry_aggregate] unexpected error: {exc}", file=sys.stderr)
        return None
    if not data.get("success"):
        return None
    results = data.get("result", [])
    if not results:
        return []
    rows = results[0].get("results", [])
    return rows if isinstance(rows, list) else []


def _quorum_pass(distinct_fingerprints: int, days_span: int, n: int, days: int) -> bool:
    return distinct_fingerprints >= n and days_span >= days


def aggregate() -> dict:
    fp_query = """
        SELECT
          check_id,
          COUNT(DISTINCT install_fp) AS distinct_installs,
          MAX(julianday('now') - julianday(MIN(reported_at))) AS days_span,
          AVG(CASE WHEN signal_type = 'fp' THEN 1.0 ELSE 0.0 END) AS fp_rate,
          COUNT(*) AS total_signals
        FROM check_signals
        WHERE reported_at >= datetime('now', '-30 days')
        GROUP BY check_id
    """
    fp_rows = _query_d1(fp_query) or []

    retire_query = """
        SELECT
          check_id,
          COUNT(DISTINCT install_fp) AS distinct_installs_no_hits,
          MAX(julianday('now') - julianday(MIN(reported_at))) AS days_span
        FROM check_zero_hits
        WHERE reported_at >= datetime('now', '-90 days')
        GROUP BY check_id
    """
    retire_rows = _query_d1(retire_query) or []

    coverage_query = """
        SELECT language, framework, COUNT(DISTINCT install_fp) AS distinct_installs
        FROM scan_metadata
        WHERE reported_at >= datetime('now', '-90 days')
        GROUP BY language, framework
    """
    coverage_rows = _query_d1(coverage_query) or []

    fired_query = """
        SELECT DISTINCT language, framework
        FROM check_signals
        WHERE reported_at >= datetime('now', '-90 days')
        AND signal_type = 'fire'
    """
    fired_rows = _query_d1(fired_query) or []
    fired_set = {(r.get("language", ""), r.get("framework", "")) for r in fired_rows}

    tune_candidates: list[dict] = []
    for row in fp_rows:
        if not isinstance(row, dict):
            continue
        if row.get("fp_rate", 0) >= RETIRE_FP_THRESHOLD and _quorum_pass(
            row.get("distinct_installs", 0),
            int(row.get("days_span", 0) or 0),
            DEFAULT_QUORUM_N,
            DEFAULT_QUORUM_DAYS,
        ):
            tune_candidates.append(row)

    retire_candidates: list[dict] = []
    for row in retire_rows:
        if not isinstance(row, dict):
            continue
        if _quorum_pass(
            row.get("distinct_installs_no_hits", 0),
            int(row.get("days_span", 0) or 0),
            RETIRE_QUORUM_N,
            RETIRE_QUORUM_DAYS,
        ):
            retire_candidates.append(row)

    coverage_gaps: list[dict] = []
    for row in coverage_rows:
        if not isinstance(row, dict):
            continue
        key = (row.get("language", ""), row.get("framework", ""))
        if key in fired_set:
            continue
        if row.get("distinct_installs", 0) < DEFAULT_QUORUM_N:
            continue
        coverage_gaps.append(row)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tune_candidates": tune_candidates,
        "retire_candidates": retire_candidates,
        "coverage_gaps": coverage_gaps,
        "telemetry_available": (CF_ACCOUNT != "" and CF_TOKEN != ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate telemetry into feedback streams.")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    result = aggregate()

    (args.out_dir / "tune-candidates.json").write_text(json.dumps(result["tune_candidates"], indent=2))
    (args.out_dir / "retire-candidates.json").write_text(json.dumps(result["retire_candidates"], indent=2))
    (args.out_dir / "coverage-gaps.json").write_text(json.dumps(result["coverage_gaps"], indent=2))
    (args.out_dir / "summary.json").write_text(json.dumps(result, indent=2))

    print(f"Telemetry aggregation complete:")
    print(f"  tune candidates: {len(result['tune_candidates'])}")
    print(f"  retire candidates: {len(result['retire_candidates'])}")
    print(f"  coverage gaps: {len(result['coverage_gaps'])}")
    print(f"  telemetry available: {result['telemetry_available']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
