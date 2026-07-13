#!/usr/bin/env python3
"""tools/security_selfaudit.py

Daily security self-audit. Re-runs, as deterministic invariants, the checks
that the 2026-07-13 adversarial security review performed by hand, so no
security regression in the pipeline can persist for more than a day undetected.
Runs from .github/workflows/security-selfaudit.yml on a daily cron; emails a
report and exits non-zero (red run) on any regression. Complements the
6-hourly liveness watchdog and the daily dual-use catch-rate scorecard.

Invariants checked:
  A. Wall soundness — the sandbox red-team harness must report a perfect catch
     rate and legitimate pass rate. A drop means a bypass has reopened.
  B. Shipped-check integrity — every check in checks/community/accepted/ (the
     tier that ships to users) must pass the wall via the SOUND AST path. A
     check that only validates via the regex fallback, or fails, means either
     a validator regression or a check that reached the shipped tier without
     sound validation.
  C. Workflow security — no GitHub Actions workflow may reference a mutable
     action ref (@master/@main), fetch-and-execute code from a mutable branch
     (curl|bash off main/master), or dispatch another workflow without the
     actions:write permission that dispatch requires. Plus actionlint clean.

Stdlib + repo modules only. Alerts via the existing SES path (send_email);
skips e-mail silently when PRESTON_NOTIFY_EMAIL / SES creds are unset.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from notify_promotion import send_email  # noqa: E402
from sandbox_validate import validate_check  # noqa: E402

ROOT = Path(__file__).parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
ACCEPTED = ROOT / "checks" / "community" / "accepted"


def audit_wall_soundness() -> list[str]:
    """A. Red-team catch rate and legitimate pass rate must be perfect."""
    issues: list[str] = []
    res = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "sandbox_redteam.py"), "--json"],
        capture_output=True, text=True, cwd=ROOT,
    )
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return ["red-team harness produced no parseable output — cannot confirm wall soundness"]
    catch = data.get("catch_rate", 0.0)
    legit = data.get("legitimate_pass_rate", 0.0)
    if catch < 1.0:
        missed = [a.get("id") for a in data.get("attacks_missed", [])]
        issues.append(f"wall catch rate {catch} < 1.0 — bypass(es) reopened: {missed[:10]}")
    if legit < data.get("threshold_legit", 0.99):
        issues.append(f"legitimate pass rate {legit} below threshold — wall rejecting valid checks")
    return issues


def audit_shipped_checks() -> list[str]:
    """B. Every shipped (accepted) check must validate via the sound AST path."""
    issues: list[str] = []
    checks = sorted(ACCEPTED.glob("*.sh"))
    if not checks:
        return issues
    for f in checks:
        result = validate_check(f)
        if not result["pass"]:
            issues.append(f"shipped check FAILS the wall: {f.name} — {result['reasons'][:2]}")
        elif result.get("validator_path") != "ast":
            # A shipped check that only passes via the regex fallback was never
            # soundly validated; investigate before it is trusted.
            issues.append(
                f"shipped check not validated via sound AST path: {f.name} "
                f"(path={result.get('validator_path')})"
            )
    return issues


def _iter_workflow_texts() -> list[tuple[Path, str]]:
    return [(f, f.read_text()) for f in sorted(WORKFLOWS.glob("*.yml"))]


def audit_workflow_security() -> list[str]:
    """C. Static security invariants across all workflow files."""
    issues: list[str] = []

    mutable_ref = re.compile(r"uses:\s*([^\s@]+)@(master|main)\b")
    curl_bash_mutable = re.compile(
        r"(curl|wget)[^\n|]*(refs/heads/(main|master)|/(main|master)/)[^\n]*\|\s*(bash|sh)"
        r"|bash\s+<\(\s*curl[^\n]*/(main|master)/"
    )
    dispatches = re.compile(r"gh\s+workflow\s+run|actions/workflows/[^/]+/dispatches")

    for path, text in _iter_workflow_texts():
        for m in mutable_ref.finditer(text):
            issues.append(f"{path.name}: action pinned to mutable @{m.group(2)} ({m.group(1)}) — pin to a SHA/tag")
        if curl_bash_mutable.search(text):
            issues.append(f"{path.name}: fetch-and-execute from a mutable branch (curl|bash off main/master)")
        if dispatches.search(text):
            # Dispatching another workflow needs actions:write. Accept either a
            # workflow-level or a job-level grant.
            if not re.search(r"actions:\s*write", text):
                issues.append(f"{path.name}: dispatches a workflow but lacks 'actions: write' permission")

    # actionlint (parse errors, unknown runner labels, expression errors).
    which = subprocess.run(["which", "actionlint"], capture_output=True, text=True)
    if which.returncode == 0:
        res = subprocess.run(
            ["actionlint", "-ignore", r"SC[0-9]+:(info|style):", *[str(p) for p in WORKFLOWS.glob("*.yml")]],
            capture_output=True, text=True, cwd=ROOT,
        )
        if res.returncode != 0:
            issues.append("actionlint reported workflow errors:\n" + (res.stdout or res.stderr).strip()[:1500])
    else:
        issues.append("actionlint not installed on the runner — cannot statically lint workflows")
    return issues


def main() -> int:
    sections = [
        ("A. Verification-wall soundness (red-team)", audit_wall_soundness()),
        ("B. Shipped-check integrity (sound AST validation)", audit_shipped_checks()),
        ("C. Workflow security (pins, fetch-exec, dispatch perms, actionlint)", audit_workflow_security()),
    ]
    all_issues = [i for _, sec in sections for i in sec]

    lines = ["Preston-Check daily security self-audit", ""]
    for title, sec in sections:
        lines.append(f"{'PASS' if not sec else 'FAIL'}  {title}")
        lines.extend(f"    - {i}" for i in sec)
    lines.append("")
    lines.append("RESULT: " + ("all invariants hold" if not all_issues
                               else f"{len(all_issues)} REGRESSION(S) — pipeline may be exposed"))
    report = "\n".join(lines)
    print(report)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        Path(summary_path).write_text("```\n" + report + "\n```\n")

    if all_issues:
        to_addr = os.environ.get("PRESTON_NOTIFY_EMAIL", "")
        if to_addr:
            ok, msg = send_email(
                to_addr,
                f"[preston-check] SECURITY SELF-AUDIT: {len(all_issues)} regression(s)",
                report,
            )
            print(f"alert e-mail: {msg}")
        else:
            print("alert e-mail skipped: PRESTON_NOTIFY_EMAIL not set")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
