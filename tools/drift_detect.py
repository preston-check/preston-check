#!/usr/bin/env python3
"""tools/drift_detect.py

Weekly drift-and-decay detection. Re-runs the validator against the
current corpora for every check in the catalog, compares to the
per-check baseline TPR/FPR recorded at last merge or last drift pass,
and flags:

  - Decayed checks: TPR drop > 10% (upstream library renamed an API,
    regex no longer matches). Auto-PR a re-synthesis attempt.
  - Noisy checks: FPR rise > 0.02 (corpus drift introduced new
    false-positive contexts). Auto-PR a tuning attempt.

Does NOT silently retire — retirement requires telemetry confirmation
from the field-feedback loop, not just corpus drift, because corpus
drift can reflect benign ecosystem evolution rather than real check
obsolescence.

Output: docs/drift-report-{date}.md plus
.preston-check/drift/flagged.json that the orchestrator consumes.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from validate_candidate import validate  # type: ignore[import-not-found]

ROOT = Path(__file__).parent.parent
CATALOG_DIRS = [
    ROOT / "checks",
    ROOT / "checks" / "core",
    ROOT / "checks" / "community" / "verified",
    ROOT / "checks" / "community" / "accepted",
]
BASELINE_FILE = ROOT / ".preston-check" / "drift" / "baseline.json"
FLAGGED_FILE = ROOT / ".preston-check" / "drift" / "flagged.json"
REPORT_DIR = ROOT / "docs"

DEFAULT_TPR_DROP = 0.10
DEFAULT_FPR_RISE = 0.02


def _load_baseline() -> dict:
    if BASELINE_FILE.is_file():
        try:
            return json.loads(BASELINE_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_baseline(b: dict) -> None:
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(b, indent=2, sort_keys=True))


def _all_checks() -> list[Path]:
    out: list[Path] = []
    for d in CATALOG_DIRS:
        if d.is_dir():
            for f in d.glob("*.sh"):
                out.append(f)
    return sorted(out)


def detect_drift(
    positive: Path,
    negative: Path,
    tpr_drop: float,
    fpr_rise: float,
) -> dict:
    baseline = _load_baseline()
    new_baseline: dict = {}
    flagged_decayed: list[dict] = []
    flagged_noisy: list[dict] = []
    summary_rows: list[dict] = []

    for check in _all_checks():
        try:
            res = validate(check, positive, negative)
        except Exception as exc:
            summary_rows.append(
                {"check": str(check), "error": str(exc), "tpr": None, "fpr": None}
            )
            continue
        m = res["metrics"]
        tpr = m["tpr"]
        fpr = m["fpr"]
        new_baseline[str(check.name)] = {
            "tpr": tpr,
            "fpr": fpr,
            "stability": m["stability"],
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        old = baseline.get(check.name, {})
        old_tpr = old.get("tpr")
        old_fpr = old.get("fpr")
        delta_tpr = (tpr - old_tpr) if isinstance(old_tpr, (int, float)) else None
        delta_fpr = (fpr - old_fpr) if isinstance(old_fpr, (int, float)) else None
        summary_rows.append(
            {
                "check": check.name,
                "tpr": tpr,
                "fpr": fpr,
                "delta_tpr": delta_tpr,
                "delta_fpr": delta_fpr,
            }
        )
        if delta_tpr is not None and delta_tpr <= -tpr_drop:
            flagged_decayed.append(
                {"check": check.name, "tpr": tpr, "old_tpr": old_tpr, "delta": delta_tpr}
            )
        if delta_fpr is not None and delta_fpr >= fpr_rise:
            flagged_noisy.append(
                {"check": check.name, "fpr": fpr, "old_fpr": old_fpr, "delta": delta_fpr}
            )

    _save_baseline(new_baseline)
    flagged = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "decayed": flagged_decayed,
        "noisy": flagged_noisy,
        "checks_evaluated": len(summary_rows),
    }
    FLAGGED_FILE.parent.mkdir(parents=True, exist_ok=True)
    FLAGGED_FILE.write_text(json.dumps(flagged, indent=2, sort_keys=True))

    return {"summary": summary_rows, "flagged": flagged}


def write_report(result: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    p = out_dir / f"drift-report-{today}.md"
    rows = result["summary"]
    flagged = result["flagged"]
    body = [
        f"# Drift Report — {today}",
        "",
        f"Checks evaluated: {flagged['checks_evaluated']}",
        f"Decayed (TPR drop): {len(flagged['decayed'])}",
        f"Noisy (FPR rise): {len(flagged['noisy'])}",
        "",
        "## Decayed checks",
        "",
    ]
    if not flagged["decayed"]:
        body.append("None.")
    for f in flagged["decayed"]:
        body.append(f"- `{f['check']}` TPR {f.get('old_tpr')} -> {f['tpr']} (delta {f['delta']:.4f})")
    body.append("")
    body.append("## Noisy checks")
    body.append("")
    if not flagged["noisy"]:
        body.append("None.")
    for f in flagged["noisy"]:
        body.append(f"- `{f['check']}` FPR {f.get('old_fpr')} -> {f['fpr']} (delta {f['delta']:.4f})")
    body.append("")
    p.write_text("\n".join(body))
    return p


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect drift in the catalog against the current corpora.")
    parser.add_argument("--positive", type=Path, required=True)
    parser.add_argument("--negative", type=Path, required=True)
    parser.add_argument("--tpr-drop", type=float, default=DEFAULT_TPR_DROP)
    parser.add_argument("--fpr-rise", type=float, default=DEFAULT_FPR_RISE)
    parser.add_argument("--report-dir", type=Path, default=REPORT_DIR)
    args = parser.parse_args()

    result = detect_drift(args.positive, args.negative, args.tpr_drop, args.fpr_rise)
    report_path = write_report(result, args.report_dir)

    flagged = result["flagged"]
    print(
        f"Drift detection complete: {flagged['checks_evaluated']} checks evaluated, "
        f"{len(flagged['decayed'])} decayed, {len(flagged['noisy'])} noisy"
    )
    print(f"Report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
