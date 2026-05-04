---
title: "Admin Portal Manual"
audience: "operator only"
date: "2026-05-04"
---

# Admin Portal

The operator's daily driver — customer management, sales pipeline,
revenue dashboard, license issuance, threat-intel triage, support
inbox, system health.

## URL

`https://admin.preston-check.com/`

Mirror at `https://preston-check-admin.pages.dev/` (same content,
also gated by the same Cloudflare Access policy).

## Auth

Cloudflare Access — operator email + 6-digit PIN sent via email.
24-hour session. Configured in Cloudflare Zero Trust → Access →
Applications → "Preston-Check Admin".

To add or change allowed emails: Zero Trust dashboard → Access →
Applications → Preston-Check Admin → Edit policy → "Operator only".
Save.

## The eight surfaces

### Customers (`#/customers`, default route)

Master list of every paying organization. Sort by MRR. Spot-check
churn-risk pills. Filter by plan / status. Click any row to open
the customer detail panel (repos, scan history, billing, support
tickets).

KPI tiles: active customers, Pro count, Enterprise count,
churn-risk-red count.

### Sales (`#/sales`)

Five-column kanban: Lead → Qualified → Demo → Trial → Closed-won.
Drag cards between stages. Pipeline ACV / weighted forecast /
win rate / avg cycle time KPIs at the top.

Sources tracked: Inbound (free-tier signup), GitHub Action
installs, Slack mentions, direct email, referrals.

### Revenue (`#/revenue`)

The CFO view. MRR / ARR / NRR (TTM) / Gross margin tiles. 12-month
MRR bar+line chart. Revenue waterfall (starting MRR + new + expansion
+ reactivation − contraction − churn = ending MRR). Eight-month
cohort retention heatmap.

Stripe is source of truth; this surface mirrors for fast queries
and offline drill-down. Reconciliation is nightly.

### Users (`#/users`)

Every individual user across every customer org. Filter by org, role,
last login, 2FA status. Stale accounts (no login > 30 days) flagged.
Suspend / unlock / reset-password actions. Audit log captures every
admin action.

### Licenses (`#/licenses`)

Issued license table with Ed25519 fingerprints. Tier pills (TRIAL /
PRO / ENT). Issue / expiry dates. Renew / Revoke actions.

License issuance triggers a hardware-token prompt on the operator's
local machine (the signing key never leaves it). Until the UI is
fully wired, issuance happens via `tools/issue-license.sh` from the
operator's terminal — see `docs/manuals/administrator-manual.md`
"Issuing a license".

### Threat-Intel (`#/threat-intel`)

Triage queue for the weekly NVD ingest. Each row is a candidate
check awaiting maintainer pattern authoring. Columns: CVE ID,
fintech-relevance score, languages affected, draft check link,
status (pending / accepted / rejected / promoted).

Click "Author pattern" to drop into a Monaco-style editor with
live regex tester against a fixture corpus. Promote to
`checks/community/accepted/` with one button.

### Support (`#/support`)

Ticket inbox. P0 / P1 / P2 priority pills. SLA timer per ticket
(median TTFR shown as a KPI). AI draft response is gated — never
auto-sent.

Sources: email to `support@preston-check.com`, Slack thread → ticket
slash command, customer-portal submitted tickets.

### System (`#/system`)

Operational pulse. Nine health-tile board covering: API,
customer portal, telemetry endpoint, D1, KV, Stripe webhook,
threat-intel cron, Docker Hub, Homebrew tap.

Build attestation panel at the bottom: tag, tarball name, SHA-256,
who published, signing key fingerprint, distribution channels. The
panel customers' auditors will ask about.

## How to navigate

Hash-routed SPA. Every surface is reachable via a permalinkable URL:

- `#/customers` (default)
- `#/sales`
- `#/revenue`
- `#/users`
- `#/licenses`
- `#/threat-intel`
- `#/support`
- `#/system`

Top bar has a search field (placeholder for future ⌘K-shortcut),
notifications bell with unread dot, and operator pill (your avatar
+ name + role).

## Source

`web/admin/` in the public repo:

```
web/admin/index.html         single-page app shell with eight sections in DOM
web/admin/styles.css         operator-density layer on the landing-page tokens
web/admin/app.js             hash router + customer-table renderer
web/admin/README.md          local-preview notes
web/admin/DEPLOY.md          Cloudflare Pages + Access setup walk-through
```

## Hosted on

Cloudflare Pages, project name `preston-check-admin`. Auto-deploys
from `web/admin/` on every master push that touches the source.
Custom domain `admin.preston-check.com` bound via Pages dashboard.
Cloudflare Access policy gates ingress.

## How to update

Edit any file under `web/admin/` and push to master. The
`admin-pages.yml` workflow auto-deploys within 60-90 seconds.

To preview locally (no Access gate, mock data only):

```bash
cd web/admin
python3 -m http.server 8081
# open http://localhost:8081/
```

To deploy manually:

```bash
gh workflow run admin-pages.yml --repo preston-check/preston-check
```

## Status

**Skeleton with mock data.** The clickable shell is live behind Access
and demonstrates every surface, but no real customer data flows
through it yet. The production wiring (impersonation, real-time KPIs
from Stripe + D1, license issuance via Touch ID, threat-intel
in-app authoring) lands per the Q4 2026 build sequence in
`docs/commercial-roadmap.md`.

## Production roadmap

Q4 2026 turns the skeleton into the operator's real daily driver:

1. **Stripe webhook integration** — Customers/Revenue tabs reflect
   reality, not mock JSON
2. **License issuance UI** — Touch-ID-prompted hardware signing
   replaces the terminal `tools/issue-license.sh` flow
3. **Threat-intel authoring editor** — Monaco editor with regex
   tester + corpus runner; promote drafts with one button
4. **Support ticket integration** — email + Slack ingest, SLA
   timers, AI draft responses (still gated)

## Cross-links

- **Administrator Manual**: `docs/manuals/administrator-manual.md`
- **Operator Runbook**: `docs/operator-runbook.md`
- **Portals + KPIs design**: `docs/portals-and-kpis.md`
- **Anonymity strategy**: `docs/strategy/anonymity-and-mystique.md`
