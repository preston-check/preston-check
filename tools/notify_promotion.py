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


def render_promotion_email(summary: dict, pr_url: str) -> tuple[str, str, str]:
    """Render subject + plain text + HTML body for a promotion notification."""
    promoted = [s for s in summary.get("summaries", []) if s.get("outcome") == "promoted"]
    would_promote = [s for s in summary.get("summaries", []) if s.get("outcome") == "would-promote"]
    rejected_sandbox = [s for s in summary.get("summaries", []) if s.get("outcome") == "rejected:sandbox"]
    rejected_validate = [s for s in summary.get("summaries", []) if s.get("outcome") == "rejected:validate"]
    rejected_adv = [s for s in summary.get("summaries", []) if s.get("outcome") == "rejected:adversarial"]

    promoted_count = len(promoted) or len(would_promote)
    if promoted_count == 0:
        return "", "", ""

    subject = f"Preston-Check: {promoted_count} new auto-merge candidate{'s' if promoted_count != 1 else ''}"
    if promoted_count == 1:
        cid = promoted[0]["canonical_id"] if promoted else would_promote[0]["canonical_id"]
        subject = f"Preston-Check: new auto-merge candidate {cid}"

    text_lines = [
        f"Preston-Check auto-merge orchestrator promoted {promoted_count} candidate{'s' if promoted_count != 1 else ''}.",
        "",
        f"Run ID:        {summary.get('ts', 'unknown')}",
        f"Auto-merge:    {summary.get('automerge_enabled', False)}",
        f"PR URL:        {pr_url}",
        "",
        "Promoted candidates:",
    ]
    for s in (promoted or would_promote):
        cid = s.get("canonical_id", "?")
        check_id = s.get("check_id", "?")
        validation = s.get("validate", {}).get("metrics", {})
        text_lines.append(
            f"  - {check_id} {cid}: tpr={validation.get('tpr', '?')} fpr={validation.get('fpr', '?')} stability={validation.get('stability', '?')}"
        )

    text_lines.extend(
        [
            "",
            f"Cycle gate outcomes:",
            f"  promoted:           {len(promoted)}",
            f"  would-promote:      {len(would_promote)} (kill switch off)",
            f"  rejected sandbox:   {len(rejected_sandbox)}",
            f"  rejected validate:  {len(rejected_validate)}",
            f"  rejected adversarial: {len(rejected_adv)}",
            "",
            "Review the PR and the signed attestation file in attestations/.",
            "Verify the attestation with: tools/attest.py verify --attestation attestations/<id>.signed.json",
            "",
            "Standing rollback if anything looks wrong:",
            "  gh secret set PRESTON_AUTOMERGE_ENABLED --repo preston-check/preston-check --body 'false'",
        ]
    )

    text_body = "\n".join(text_lines)

    html_body = f"""<!DOCTYPE html>
<html><body style="font-family: -apple-system, sans-serif; line-height: 1.5;">
<h2 style="color: #16a34a;">Preston-Check: {promoted_count} new auto-merge candidate{'s' if promoted_count != 1 else ''}</h2>
<p><strong>Run:</strong> {summary.get('ts', 'unknown')}<br>
<strong>Auto-merge:</strong> {summary.get('automerge_enabled', False)}<br>
<strong>PR:</strong> <a href="{pr_url}">{pr_url}</a></p>
<h3>Promoted candidates</h3>
<ul>"""
    for s in (promoted or would_promote):
        cid = s.get("canonical_id", "?")
        check_id = s.get("check_id", "?")
        validation = s.get("validate", {}).get("metrics", {})
        html_body += (
            f"<li><code>{check_id}</code> <strong>{cid}</strong>: "
            f"tpr={validation.get('tpr', '?')} "
            f"fpr={validation.get('fpr', '?')} "
            f"stability={validation.get('stability', '?')}</li>"
        )
    html_body += f"""</ul>
<h3>Cycle outcomes</h3>
<ul>
  <li>Promoted: {len(promoted)}</li>
  <li>Rejected at sandbox: {len(rejected_sandbox)}</li>
  <li>Rejected at validation: {len(rejected_validate)}</li>
  <li>Rejected at adversarial: {len(rejected_adv)}</li>
</ul>
<p style="color: #6b7280; font-size: 0.9em;">
Review the signed attestation in <code>attestations/</code> before merging.<br>
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
