#!/usr/bin/env python3
"""tools/update_landing_stats.py

Reconcile the public landing page's check-count claims with the actual
shipped catalog, so preston-check.com never advertises a stale number
after threat-intel promotions land.

Counting mirrors runner discovery in preston-check.sh (CHECK_DIRS):
checks/*.sh plus checks/community/verified/*.sh plus
checks/community/accepted/*.sh — checks/community/proposed/ is excluded
exactly as the runner excludes it by default — plus the deep
smart-contract module (modules/smart-contract-audit/checks/*.sh), which
the landing page has always counted in its catalog total.

The repo copy of web/landing/index.html is rewritten in place (not
substituted at deploy time) so the file in git always matches what is
live. Idempotent: exits 0 with "unchanged" when the page is accurate.

Usage:
  python3 tools/update_landing_stats.py           # rewrite if stale
  python3 tools/update_landing_stats.py --check   # exit 2 if stale, no write

Run automatically by tools/watchdog.py (see docs/pipeline-reliability.md).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
LANDING = ROOT / "web" / "landing" / "index.html"


def catalog_counts(root: Path = ROOT) -> dict[str, int]:
    core = len(list((root / "checks").glob("*.sh")))
    verified = len(list((root / "checks" / "community" / "verified").glob("*.sh")))
    accepted = len(list((root / "checks" / "community" / "accepted").glob("*.sh")))
    deep = len(list((root / "modules" / "smart-contract-audit" / "checks").glob("*.sh")))
    promoted = verified + accepted
    return {
        "core": core,
        "promoted": promoted,
        "deep": deep,
        "total": core + promoted + deep,
    }


def _substitutions(c: dict[str, int]) -> list[tuple[str, str]]:
    """(pattern, replacement) pairs. Migrations from the pre-2026-07 copy
    run first; the anchored steady-state patterns keep every later run
    idempotent against the canonical wording they produce."""
    total, core, promoted, deep = c["total"], c["core"], c["promoted"], c["deep"]
    return [
        # --- one-time migrations from the legacy hardcoded copy ---
        (
            r"\d+ hand-curated checks across 33 reputable frameworks "
            r"— PCI-DSS, MiCA, DORA, NYDFS, OWASP, NIST, CCSS, FATF — with",
            f"{total} security checks across 33 reputable frameworks "
            f"— PCI-DSS, MiCA, DORA, NYDFS, OWASP, NIST, CCSS, FATF — "
            f"hand-curated and auto-evolved from live threat intelligence, with",
        ),
        (
            r"\d+ main \+ \d+ deep smart-contract\.",
            f"{core} hand-curated main + {promoted} threat-intel-promoted "
            f"+ {deep} deep smart-contract.",
        ),
        # --- steady-state anchors (idempotent) ---
        (r"\d+(?= automated security checks across 33 frameworks)", str(total)),
        (r"\d+(?= checks across 33 frameworks)", str(total)),
        (r"\d+(?= security checks across 33 reputable frameworks)", str(total)),
        (r"(?<=Catalog of )\d+(?= checks)", str(total)),
        (r"\d+(?= hand-curated main)", str(core)),
        (r"\d+(?= threat-intel-promoted)", str(promoted)),
        (r"\d+(?= deep smart-contract)", str(deep)),
        (r"(?<=Full )\d+(?=-check catalog)", str(total)),
        (
            r'(<div class="n">)\d+(</div><div class="l">Checks in catalog</div>)',
            rf"\g<1>{total}\g<2>",
        ),
    ]


def apply(root: Path = ROOT, write: bool = True) -> tuple[bool, str]:
    """Returns (changed, summary). With write=False, reports without touching
    the file."""
    counts = catalog_counts(root)
    page = root / "web" / "landing" / "index.html"
    src = page.read_text()
    out = src
    for pattern, repl in _substitutions(counts):
        out = re.sub(pattern, repl, out)

    summary = (
        f"catalog: {counts['total']} total "
        f"({counts['core']} core + {counts['promoted']} promoted "
        f"+ {counts['deep']} deep)"
    )
    if out == src:
        return False, f"landing page already accurate — {summary}"
    if write:
        page.write_text(out)
    return True, f"landing page updated — {summary}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="report staleness, no write; exit 2 if stale")
    args = ap.parse_args()

    changed, summary = apply(write=not args.check)
    print(summary)
    if args.check and changed:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
