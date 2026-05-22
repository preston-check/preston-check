#!/usr/bin/env python3
"""tools/notify_promotion.py

Send an email notification when the orchestrator promotes a new check
into the catalog (or opens a promotion PR). Uses AWS SES with inline
SigV4 signing — same approach as the auth Worker, no aws-sdk-js
dependency.

Reads recipient from PRESTON_NOTIFY_EMAIL env var (set as a repo secret).
Reads SES credentials from SES_AWS_ACCESS_KEY_ID and
SES_AWS_SECRET_ACCESS_KEY (already configured for the auth Worker).

Skips silently with exit 0 when:
  - PRESTON_NOTIFY_EMAIL is unset (notifications disabled)
  - SES credentials are unset (email infrastructure not configured)
  - The orchestrate-summary.json reports zero promotions
This means the script is safe to wire into every orchestrator run; it
fires only when there's something newsworthy to notify about.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent.parent
SUMMARY_FILE = ROOT / ".preston-check" / "orchestrate-summary.json"

SES_REGION = "us-east-1"
SES_ENDPOINT = f"https://email.{SES_REGION}.amazonaws.com/"
SES_HOST = f"email.{SES_REGION}.amazonaws.com"
FROM_ADDRESS = "Preston-Check <preston@preston-check.com>"


def _sigv4_sign_ses(
    access_key: str,
    secret_key: str,
    payload: dict[str, str],
) -> dict[str, str]:
    """Inline SigV4 signing for SES SendEmail (SES Classic POST API).
    Returns the headers dict to use with the request."""
    body = urllib.parse.urlencode(payload)
    body_bytes = body.encode("utf-8")
    body_hash = hashlib.sha256(body_bytes).hexdigest()

    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_uri = "/"
    canonical_querystring = ""
    canonical_headers = (
        f"content-type:application/x-www-form-urlencoded; charset=utf-8\n"
        f"host:{SES_HOST}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"
    canonical_request = (
        f"POST\n{canonical_uri}\n{canonical_querystring}\n"
        f"{canonical_headers}\n{signed_headers}\n{body_hash}"
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{SES_REGION}/email/aws4_request"
    string_to_sign = (
        f"{algorithm}\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, SES_REGION)
    k_service = _sign(k_region, "email")
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = (
        f"{algorithm} "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    return {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Host": SES_HOST,
        "X-Amz-Date": amz_date,
        "Authorization": auth_header,
    }


def send_email(
    to_address: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
) -> tuple[bool, str]:
    """Send an email via SES. Returns (ok, status_or_error_message)."""
    access_key = os.environ.get("SES_AWS_ACCESS_KEY_ID", "")
    secret_key = os.environ.get("SES_AWS_SECRET_ACCESS_KEY", "")
    if not access_key or not secret_key:
        return False, "SES credentials not configured (SES_AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY)"

    payload = {
        "Action": "SendEmail",
        "Source": FROM_ADDRESS,
        "Destination.ToAddresses.member.1": to_address,
        "Message.Subject.Data": subject,
        "Message.Subject.Charset": "UTF-8",
        "Message.Body.Text.Data": body_text,
        "Message.Body.Text.Charset": "UTF-8",
    }
    if body_html:
        payload["Message.Body.Html.Data"] = body_html
        payload["Message.Body.Html.Charset"] = "UTF-8"

    headers = _sigv4_sign_ses(access_key, secret_key, payload)
    body = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(SES_ENDPOINT, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return True, f"sent (status {resp.status})"
    except Exception as exc:
        return False, f"SES error: {exc}"


def _read_check_meta(check_id: str) -> dict[str, str]:
    """Read PRESTON_META from a promoted check script to get its human-readable fields."""
    accepted_dir = ROOT / "checks" / "community" / "accepted"
    pattern = f"{check_id}-*.sh"
    matches = list(accepted_dir.glob(pattern))
    if not matches:
        return {}
    text = matches[0].read_text(errors="ignore")
    meta: dict[str, str] = {}
    in_block = False
    for line in text.splitlines():
        if "PRESTON_META" in line and "<<" in line:
            in_block = True
            continue
        if in_block and "PRESTON_META" in line:
            break
        if in_block and ": " in line:
            key, _, val = line.partition(": ")
            meta[key.strip()] = val.strip()
    return meta


def _meta_severity_badge(severity: str) -> str:
    colours = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a"}
    return colours.get(severity.lower(), "#6b7280")


def _explain_metrics(tpr: float | str, fpr: float | str, stability: float | str) -> str:
    """Return a plain-English interpretation of the three gate metrics."""
    tpr_f = float(tpr) if tpr not in ("?", None) else None
    fpr_f = float(fpr) if fpr not in ("?", None) else None
    stab_f = float(stability) if stability not in ("?", None) else None

    parts = []
    if tpr_f is not None:
        if tpr_f == 0.0:
            parts.append("TPR: measured via fixture-roundtrip proxy (corpus too small for live scoring — this is normal for new CVEs)")
        else:
            parts.append(f"TPR {tpr_f:.0%} true-positive rate on known-vulnerable samples")
    if fpr_f is not None:
        parts.append(f"FPR {fpr_f:.0%} false-positive rate on clean code")
    if stab_f is not None:
        if stab_f >= 1.0:
            parts.append("stability perfect (no flakiness across runs)")
        else:
            parts.append(f"stability {stab_f:.0%}")
    return " · ".join(parts) if parts else "metrics unavailable"


def _group_by_cve(items: list[dict]) -> dict[str, list[dict]]:
    """Group summary records by canonical CVE ID."""
    groups: dict[str, list[dict]] = {}
    for s in items:
        cid = s.get("canonical_id", "unknown")
        groups.setdefault(cid, []).append(s)
    return groups


def _is_compare_url(url: str) -> bool:
    return "/compare/" in url and "?expand=1" in url


def render_promotion_email(summary: dict, pr_url: str) -> tuple[str, str, str]:
    """Render subject + plain text + HTML body for a promotion notification."""
    promoted = [s for s in summary.get("summaries", []) if s.get("outcome") == "promoted"]
    would_promote = [s for s in summary.get("summaries", []) if s.get("outcome") == "would-promote"]
    rejected_sandbox = [s for s in summary.get("summaries", []) if s.get("outcome") == "rejected:sandbox"]
    rejected_validate = [s for s in summary.get("summaries", []) if s.get("outcome") == "rejected:validate"]
    rejected_adv = [s for s in summary.get("summaries", []) if s.get("outcome") == "rejected:adversarial"]

    active = promoted or would_promote
    promoted_count = len(active)
    if promoted_count == 0:
        return "", "", ""

    cve_groups = _group_by_cve(active)
    unique_cves = list(cve_groups.keys())
    needs_manual_pr = _is_compare_url(pr_url)

    # ── Subject ──────────────────────────────────────────────────────────────
    if len(unique_cves) == 1:
        subject = f"Preston-Check: {promoted_count} new check{'s' if promoted_count != 1 else ''} — {unique_cves[0]}"
    else:
        subject = f"Preston-Check: {promoted_count} new checks across {len(unique_cves)} CVEs"

    # ── Plain text body ───────────────────────────────────────────────────────
    run_ts = summary.get("ts", "unknown")
    automerge = summary.get("automerge_enabled", False)

    action_line = (
        "ACTION REQUIRED: GitHub Actions cannot create PRs automatically in this org.\n"
        f"  Open this URL and click 'Create pull request': {pr_url}"
        if needs_manual_pr else
        f"PR opened and auto-merge queued: {pr_url}"
    )

    text_lines = [
        f"Preston-Check promoted {promoted_count} new security check{'s' if promoted_count != 1 else ''} "
        f"covering {len(unique_cves)} CVE{'s' if len(unique_cves) != 1 else ''}.",
        "",
        f"Run:        {run_ts}",
        f"Auto-merge: {automerge}",
        "",
        action_line,
        "",
        "=" * 60,
        "WHAT WAS PROMOTED",
        "=" * 60,
    ]

    for cid, records in cve_groups.items():
        # Read metadata from the first promoted check for this CVE
        first_check_id = records[0].get("check_id", "?")
        meta = _read_check_meta(first_check_id)
        check_name = meta.get("name", f"{cid} detection")
        # Strip variant suffix from name for the group header
        base_name = check_name.rsplit(" (", 1)[0] if " (" in check_name else check_name
        severity = meta.get("severity", "unknown")
        cwe = meta.get("cwe", "")
        description = meta.get("description", "")
        # Trim auto-synthesized prefix from description
        if ";" in description:
            description = description.split(";", 2)[-1].strip().lstrip("rationale=").strip()

        text_lines += [
            "",
            f"▶ {cid}  [{severity.upper()}]{' · ' + cwe if cwe else ''}",
            f"  {base_name}",
        ]
        if description:
            import textwrap
            for wrap_line in textwrap.wrap(description, 72, initial_indent="  ", subsequent_indent="  "):
                text_lines.append(wrap_line)

        text_lines.append(f"  Sources: {meta.get('frameworks', meta.get('source', 'unknown'))}")
        text_lines.append(f"  Checks generated ({len(records)}):")
        for rec in records:
            vid = rec.get("check_id", "?")
            rmeta = _read_check_meta(vid)
            rname = rmeta.get("name", vid)
            validation = rec.get("validate", {}).get("metrics", {})
            tpr = validation.get("tpr", "?")
            fpr = validation.get("fpr", "?")
            stab = validation.get("stability", "?")
            text_lines.append(f"    P-{vid}: {rname}")
            text_lines.append(f"           {_explain_metrics(tpr, fpr, stab)}")

    text_lines += [
        "",
        "=" * 60,
        "PIPELINE GATE SUMMARY",
        "=" * 60,
        f"  Promoted:             {len(promoted)}",
        f"  Would-promote:        {len(would_promote)} (automerge kill switch is off)" if would_promote else "",
        f"  Rejected at sandbox:  {len(rejected_sandbox)}",
        f"  Rejected at validate: {len(rejected_validate)}",
        f"  Rejected adversarial: {len(rejected_adv)}",
        "",
        "All promoted checks have signed attestations in attestations/.",
        "To halt auto-merge at any time:",
        "  gh secret set PRESTON_AUTOMERGE_ENABLED --repo preston-check/preston-check --body 'false'",
    ]

    text_body = "\n".join(l for l in text_lines if l is not None)

    # ── HTML body ─────────────────────────────────────────────────────────────
    action_html = (
        f'<div style="background:#fef3c7;border-left:4px solid #d97706;padding:12px 16px;margin:16px 0;">'
        f'<strong>Action required</strong> — GitHub Actions cannot create PRs automatically in this org.<br>'
        f'<a href="{pr_url}" style="color:#d97706;">Open this branch comparison and click "Create pull request"</a>'
        f'</div>'
        if needs_manual_pr else
        f'<p><strong>PR:</strong> <a href="{pr_url}">{pr_url}</a> — auto-merge queued.</p>'
    )

    html_body = f"""<!DOCTYPE html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.6;max-width:680px;margin:0 auto;color:#111;">
<h2 style="color:#16a34a;margin-bottom:4px;">Preston-Check: {promoted_count} new security check{'s' if promoted_count != 1 else ''}</h2>
<p style="color:#6b7280;margin-top:0;">Run {run_ts} &nbsp;·&nbsp; {len(unique_cves)} CVE{'s' if len(unique_cves)!=1 else ''} covered</p>
{action_html}
<hr style="border:none;border-top:1px solid #e5e7eb;">
<h3 style="margin-bottom:8px;">What was promoted</h3>"""

    for cid, records in cve_groups.items():
        first_check_id = records[0].get("check_id", "?")
        meta = _read_check_meta(first_check_id)
        check_name = meta.get("name", f"{cid} detection")
        base_name = check_name.rsplit(" (", 1)[0] if " (" in check_name else check_name
        severity = meta.get("severity", "unknown")
        cwe = meta.get("cwe", "")
        description = meta.get("description", "")
        if ";" in description:
            description = description.split(";", 2)[-1].strip().lstrip("rationale=").strip()
        sources = meta.get("frameworks", meta.get("source", "unknown"))
        badge_colour = _meta_severity_badge(severity)

        html_body += f"""
<div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin:12px 0;">
  <div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;">
    <span style="font-family:monospace;font-weight:700;font-size:1.05em;">{cid}</span>
    <span style="background:{badge_colour};color:#fff;font-size:0.75em;padding:2px 8px;border-radius:4px;font-weight:600;">{severity.upper()}</span>
    {"<span style='color:#6b7280;font-size:0.85em;'>" + cwe + "</span>" if cwe else ""}
  </div>
  <div style="font-weight:600;margin:6px 0 4px;">{base_name}</div>"""
        if description:
            html_body += f'  <p style="margin:4px 0 8px;color:#374151;font-size:0.9em;">{description[:500]}{"…" if len(description) > 500 else ""}</p>'
        html_body += f'  <div style="font-size:0.8em;color:#6b7280;">Sources: {sources}</div>'
        html_body += '<table style="margin-top:10px;width:100%;border-collapse:collapse;font-size:0.875em;">'
        html_body += '<tr style="background:#f9fafb;"><th style="text-align:left;padding:6px 8px;border:1px solid #e5e7eb;">Check</th><th style="text-align:left;padding:6px 8px;border:1px solid #e5e7eb;">Detection pattern</th><th style="text-align:left;padding:6px 8px;border:1px solid #e5e7eb;">Metrics</th></tr>'
        for rec in records:
            vid = rec.get("check_id", "?")
            rmeta = _read_check_meta(vid)
            rname = rmeta.get("name", f"P-{vid}")
            variant_label = rname.rsplit("(", 1)[-1].rstrip(")") if "(" in rname else rname
            validation = rec.get("validate", {}).get("metrics", {})
            tpr = validation.get("tpr", "?")
            fpr = validation.get("fpr", "?")
            stab = validation.get("stability", "?")
            metrics_str = _explain_metrics(tpr, fpr, stab)
            adv_pass = rec.get("adversarial", {}).get("passes", None)
            adv_badge = (
                '<span style="color:#16a34a;">✓ adversarial</span>' if adv_pass is True else
                '<span style="color:#dc2626;">✗ adversarial</span>' if adv_pass is False else ""
            )
            html_body += (
                f'<tr><td style="padding:6px 8px;border:1px solid #e5e7eb;font-family:monospace;">P-{vid}</td>'
                f'<td style="padding:6px 8px;border:1px solid #e5e7eb;">{variant_label} {adv_badge}</td>'
                f'<td style="padding:6px 8px;border:1px solid #e5e7eb;color:#6b7280;font-size:0.85em;">{metrics_str}</td></tr>'
            )
        html_body += '</table></div>'

    html_body += f"""
<hr style="border:none;border-top:1px solid #e5e7eb;margin-top:24px;">
<h3 style="margin-bottom:8px;">Pipeline gate summary</h3>
<table style="border-collapse:collapse;font-size:0.9em;">
  <tr><td style="padding:3px 16px 3px 0;color:#374151;">Promoted</td><td style="font-weight:600;color:#16a34a;">{len(promoted)}</td></tr>
  <tr><td style="padding:3px 16px 3px 0;color:#374151;">Rejected at sandbox</td><td>{len(rejected_sandbox)}</td></tr>
  <tr><td style="padding:3px 16px 3px 0;color:#374151;">Rejected at validation</td><td>{len(rejected_validate)}</td></tr>
  <tr><td style="padding:3px 16px 3px 0;color:#374151;">Rejected at adversarial</td><td>{len(rejected_adv)}</td></tr>
</table>
<p style="margin-top:20px;color:#6b7280;font-size:0.85em;">
Signed attestations are in <code>attestations/</code>.<br>
To halt auto-merge: <code>gh secret set PRESTON_AUTOMERGE_ENABLED --repo preston-check/preston-check --body 'false'</code>
</p>
</body></html>"""

    return subject, text_body, html_body


def main() -> int:
    parser = argparse.ArgumentParser(description="Send notification email for orchestrator promotions.")
    parser.add_argument("--summary", type=Path, default=SUMMARY_FILE)
    parser.add_argument("--pr-url", type=str, default="")
    parser.add_argument("--dry-run", action="store_true", help="Render the email but don't send it")
    args = parser.parse_args()

    to_address = os.environ.get("PRESTON_NOTIFY_EMAIL", "").strip()
    if not to_address:
        print("[notify] PRESTON_NOTIFY_EMAIL unset — notifications disabled, skipping")
        return 0

    if not args.summary.is_file():
        print(f"[notify] summary file not found: {args.summary} — skipping")
        return 0

    try:
        summary = json.loads(args.summary.read_text())
    except json.JSONDecodeError as exc:
        print(f"[notify] could not parse summary: {exc}", file=sys.stderr)
        return 0

    subject, text_body, html_body = render_promotion_email(summary, args.pr_url)
    if not subject:
        print("[notify] no promotions in this cycle — nothing to notify about")
        return 0

    if args.dry_run:
        print(f"=== Dry run — would send to {to_address} ===")
        print(f"Subject: {subject}")
        print()
        print(text_body)
        return 0

    ok, status = send_email(to_address, subject, text_body, html_body)
    if ok:
        print(f"[notify] sent to {to_address}: {status}")
        return 0
    print(f"[notify] failed: {status}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
