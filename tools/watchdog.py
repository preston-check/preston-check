#!/usr/bin/env python3
"""tools/watchdog.py

Out-of-band health monitor for the preston-check automation. Runs every
six hours from .github/workflows/pipeline-watchdog.yml, observing workflow
run outcomes through the GitHub API — deliberately from OUTSIDE the
workflows it watches, because a workflow file that fails to parse executes
zero steps and can never report its own death (the June 2026 release.yml
incident; see docs/pipeline-reliability.md).

Duties, in order:
  1. Detect: workflow runs concluded failure / startup_failure / timed_out
     in the lookback window.
  2. Auto-heal (transient): re-run first-attempt failures once. Second
     failures escalate instead of looping.
  3. Auto-heal (release): newest v* tag with no GitHub release means the
     release pipeline died after tagging — dispatch release.yml for that
     tag, unless a release run is already active or the tag has burned
     three attempts (then escalate).
  4. Auto-heal (site accuracy): reconcile the landing-page check count via
     tools/update_landing_stats.py; commit and dispatch pages.yml (pushes
     made with the Actions token do not fire on:push workflows).
  5. Alert: e-mail a report through the promotion SES path when anything
     was healed or needs a human. Quiet windows send nothing.

Stdlib only. Credentials: GITHUB_TOKEN (API), PRESTON_NOTIFY_EMAIL +
SES_AWS_* (alerts, optional — skipped silently when unset, same contract
as tools/notify_promotion.py).

Usage:
  python3 tools/watchdog.py             # full run (intended for CI)
  python3 tools/watchdog.py --dry-run   # observe + report, mutate nothing
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from notify_promotion import send_email  # noqa: E402
from update_landing_stats import apply as apply_landing_stats  # noqa: E402

ROOT = Path(__file__).parent.parent
API = "https://api.github.com"
REPO = os.environ.get("GITHUB_REPOSITORY", "preston-check/preston-check")

BAD_CONCLUSIONS = {"failure", "startup_failure", "timed_out"}
# Never auto-rerun ourselves; a watchdog rerun loop helps nobody.
SELF_NAME = "Pipeline watchdog"
# Workflows that perform stateful, non-idempotent operations (merging PRs,
# pushing tags, publishing releases) must NOT be auto-re-run: the original run
# may have partially completed (e.g. merged its PR), so a re-run re-does git
# operations that now conflict with the changed repo state and fails again —
# exactly what happened on 2026-07-13. Escalate these instead. Recovery is
# handled elsewhere: the next scheduled orchestrate cycle processes pending
# candidates fresh, and tag-without-release is reconciled by release dispatch.
NO_RERUN_WORKFLOWS = {
    "Threat-intel orchestrate",
    "Auto-tag on threat-intel merge",
    "Release",
}
RELEASE_DISPATCH_CAP = 3  # failed release runs per tag before escalating
PROMOTION_TITLE_PREFIX = "auto: threat-intel orchestrate"
PROMOTION_STUCK_HOURS = 24


def _gh(path: str, method: str = "GET", body: dict | None = None) -> tuple[int, dict | list | None]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise SystemExit("GITHUB_TOKEN is required")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{API}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "preston-check-watchdog",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def recent_runs(lookback_hours: int) -> tuple[list[dict], dict[int, str]]:
    """Bad runs in the window, plus workflow_id -> latest successful
    created_at, so failures already superseded by a newer green run of the
    same workflow can be skipped instead of re-run or escalated."""
    since = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(hours=lookback_hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    bad: list[dict] = []
    last_success: dict[int, str] = {}
    for page in range(1, 4):
        status, payload = _gh(
            f"/repos/{REPO}/actions/runs?status=completed&per_page=100"
            f"&page={page}&created=%3E%3D{since}"
        )
        if status != 200 or not payload:
            break
        batch = payload.get("workflow_runs", [])
        for r in batch:
            if r.get("conclusion") in BAD_CONCLUSIONS:
                bad.append(r)
            elif r.get("conclusion") == "success":
                wf = r["workflow_id"]
                if r["created_at"] > last_success.get(wf, ""):
                    last_success[wf] = r["created_at"]
        if len(batch) < 100:
            break
    return bad, last_success


def rerun_failed(run: dict) -> tuple[bool, str]:
    status, _ = _gh(f"/repos/{REPO}/actions/runs/{run['id']}/rerun-failed-jobs", method="POST", body={})
    if status == 201:
        return True, "re-run queued"
    return False, f"re-run refused (HTTP {status})"


def latest_semver_tag() -> str | None:
    status, tags = _gh(f"/repos/{REPO}/tags?per_page=100")
    if status != 200 or not tags:
        return None
    versions = []
    for t in tags:
        m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", t["name"])
        if m:
            versions.append((tuple(int(g) for g in m.groups()), t["name"]))
    return max(versions)[1] if versions else None


def release_exists(tag: str) -> bool:
    status, _ = _gh(f"/repos/{REPO}/releases/tags/{tag}")
    return status == 200


def release_runs_snapshot() -> tuple[bool, int]:
    """(any release run queued/in progress, failed release runs in last 7d)."""
    active = False
    for st in ("queued", "in_progress"):
        status, payload = _gh(f"/repos/{REPO}/actions/workflows/release.yml/runs?status={st}&per_page=10")
        if status == 200 and payload and payload.get("total_count", 0) > 0:
            active = True
    week_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
    failed = 0
    status, payload = _gh(f"/repos/{REPO}/actions/workflows/release.yml/runs?status=completed&per_page=50")
    if status == 200 and payload:
        for r in payload.get("workflow_runs", []):
            created = datetime.datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
            if created >= week_ago and r.get("conclusion") in BAD_CONCLUSIONS:
                failed += 1
    return active, failed


def dispatch_workflow(filename: str, inputs: dict | None = None) -> tuple[bool, str]:
    body: dict = {"ref": "master"}
    if inputs:
        body["inputs"] = inputs
    status, _ = _gh(f"/repos/{REPO}/actions/workflows/{filename}/dispatches", method="POST", body=body)
    if status == 204:
        return True, "dispatched"
    return False, f"dispatch refused (HTTP {status})"


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)


def reconcile_landing(dry_run: bool, healed: list[str], escalations: list[str]) -> None:
    changed, summary = apply_landing_stats(ROOT, write=not dry_run)
    if not changed:
        return
    if dry_run:
        healed.append(f"[dry-run] {summary}")
        return
    _git("config", "user.name", "preston-check-bot")
    _git("config", "user.email", "bot@preston-check.com")
    _git("add", "web/landing/index.html")
    commit = _git("commit", "-m", "site: reconcile landing-page check count (watchdog)")
    if commit.returncode != 0:
        escalations.append(f"landing commit failed: {commit.stderr.strip()[:200]}")
        return
    push = _git("push", "origin", "HEAD:master")
    if push.returncode != 0:
        # Likely a race with a concurrent merge; next tick retries cleanly.
        escalations.append(f"landing push failed (will retry next tick): {push.stderr.strip()[:200]}")
        return
    ok, msg = dispatch_workflow("pages.yml")
    healed.append(f"{summary}; committed and pages deploy {msg if ok else 'NOT ' + msg}")
    if not ok:
        escalations.append(f"pages.yml {msg} after landing commit — site may lag until next human push")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="observe and report; mutate nothing")
    ap.add_argument("--lookback-hours", type=int, default=25)
    args = ap.parse_args()

    healed: list[str] = []
    escalations: list[str] = []

    # 1+2 — detect bad runs, re-run first-attempt failures once.
    bad_runs, last_success = recent_runs(args.lookback_hours)
    for run in bad_runs:
        label = f"{run['name']} #{run['run_number']} ({run['conclusion']}, attempt {run['run_attempt']}) {run['html_url']}"
        if run["created_at"] < last_success.get(run["workflow_id"], ""):
            # A newer run of this workflow already succeeded — the failure
            # was fixed or superseded; re-running the old commit is noise.
            continue
        if run["conclusion"] == "startup_failure":
            escalations.append(
                f"UNPARSEABLE WORKFLOW FILE — {label}. No in-band alert can ever "
                f"fire for this file; fix {run.get('path', 'the workflow file')} now."
            )
        elif run["name"] == SELF_NAME:
            escalations.append(f"watchdog's own run failed — {label}")
        elif run["name"] in NO_RERUN_WORKFLOWS:
            # Stateful workflow — a re-run would redo git/release operations that
            # conflict with the now-changed repo state. Escalate; recovery comes
            # from the next scheduled cycle / release reconciliation, not a re-run.
            escalations.append(f"stateful workflow failed (not auto-re-run — next cycle recovers) — {label}")
        elif run["run_attempt"] == 1:
            if args.dry_run:
                healed.append(f"[dry-run] would re-run: {label}")
            else:
                ok, msg = rerun_failed(run)
                (healed if ok else escalations).append(f"{msg}: {label}")
        else:
            escalations.append(f"failed again after re-run — {label}")

    # 3 — a tag with no release means the release pipeline died after tagging.
    tag = latest_semver_tag()
    if tag and not release_exists(tag):
        active, failed_recently = release_runs_snapshot()
        if active:
            healed.append(f"release for {tag} missing but a release run is already active — waiting")
        elif failed_recently >= RELEASE_DISPATCH_CAP:
            escalations.append(
                f"release for {tag} missing and {failed_recently} release runs failed "
                f"in 7d — dispatch cap hit, human needed"
            )
        elif args.dry_run:
            healed.append(f"[dry-run] would dispatch release.yml for {tag}")
        else:
            ok, msg = dispatch_workflow("release.yml", {"tag": tag})
            (healed if ok else escalations).append(f"release.yml for {tag}: {msg}")

    # 4 — promotion PRs must merge within a day; orchestrate merges its own
    # PR (2026-07-13 fix), so anything sitting open means that leg broke
    # again. NOT auto-merged here: stale promotion PRs carry per-run file
    # numbering that collides once newer batches land — a human must look.
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(hours=PROMOTION_STUCK_HOURS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    stuck: list[dict] = []
    for page in range(1, 6):
        status, prs = _gh(f"/repos/{REPO}/pulls?state=open&per_page=100&page={page}")
        if status != 200 or not prs:
            break
        stuck.extend(
            p for p in prs
            if p["title"].startswith(PROMOTION_TITLE_PREFIX) and p["created_at"] < cutoff
        )
        if len(prs) < 100:
            break
    if stuck:
        oldest = min(p["created_at"] for p in stuck)
        escalations.append(
            f"{len(stuck)} promotion PR(s) open for >{PROMOTION_STUCK_HOURS}h "
            f"(oldest {oldest}) — the auto-merge leg is not landing them; "
            f"e.g. {stuck[0]['html_url']}"
        )

    # 5 — keep the public check count honest.
    reconcile_landing(args.dry_run, healed, escalations)

    # 6 — report.
    lines = ["Pipeline watchdog report", f"repo: {REPO}", ""]
    if healed:
        lines += ["Auto-healed / in progress:"] + [f"  - {h}" for h in healed] + [""]
    if escalations:
        lines += ["NEEDS ATTENTION:"] + [f"  - {e}" for e in escalations] + [""]
    if not healed and not escalations:
        lines.append("All quiet — no failed runs, releases reconciled, site accurate.")
    report = "\n".join(lines)
    print(report)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        Path(summary_path).write_text("```\n" + report + "\n```\n")

    # An alert that silently fails to send leaves a blind watchdog looking
    # healthy — the exact class this watchdog exists to prevent. So when there
    # is something to report, a failure (or absence) of the alert channel must
    # turn the run RED rather than exit 0. A red run is visible in the Actions
    # tab and reaches the actor via GitHub's own notifications.
    alert_ok = True
    if (healed or escalations) and not args.dry_run:
        to_addr = os.environ.get("PRESTON_NOTIFY_EMAIL", "")
        if to_addr:
            n_heal, n_esc = len(healed), len(escalations)
            subject = f"[preston-check] watchdog: {n_heal} auto-healed, {n_esc} need attention"
            ok, msg = send_email(to_addr, subject, report)
            print(f"alert e-mail: {msg}")
            alert_ok = ok
        else:
            print("alert e-mail skipped: PRESTON_NOTIFY_EMAIL not set")
            # Escalations with no way to notify a human is a real failure;
            # auto-healed-only with no recipient configured is acceptable.
            alert_ok = not escalations

    if not alert_ok:
        print("::error::watchdog could not deliver its alert — see report above", file=sys.stderr)
        return 1
    # Surface unresolved escalations as a non-zero exit too, so the run is red
    # even when the e-mail went out: the operator still has work to do.
    if escalations and not args.dry_run:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
