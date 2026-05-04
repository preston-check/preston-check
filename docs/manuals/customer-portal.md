---
title: "Customer Portal Manual"
audience: "paying customers, customer-success staff"
date: "2026-05-04"
---

# Customer Portal

The SaaS dashboard where paying customers (Pro, Enterprise) consume
scanner output and produce auditor-ready deliverables.

## URL

`https://app.preston-check.com/`

Mirror at `https://preston-check-customer.pages.dev/` (Cloudflare's
internal Pages URL — always reachable).

## Status

**Skeleton with mock data.** The clickable shell is live and demonstrates
every surface, but no real customer data flows through it yet. The
production wiring (auth, billing, scan-result ingestion, license
issuance) lands per the Q3 2026 build sequence in
`docs/commercial-roadmap.md`.

## The five surfaces

### Home (`#/home`, default route)

Score-as-hero panel: the customer's current letter grade (A–F) and
numeric score in a navy-emerald gradient panel. Below it: four KPI
tiles, a 90-day score sparkline, top-2 critical findings preview,
framework-coverage progress bars across PCI-DSS / SOC 2 / MiCA /
OWASP API.

The score-as-headline pattern is the single most underrated UX move
in security tooling — see `docs/strategy/moat-strategy.md`.

### Repos (`#/repos`)

Connected-repository list with one row per repo. Columns: name,
language, current letter grade (color-coded chip), critical/high
finding pills, last-scan timestamp, 30-day mini-sparkline trend.
Click any row to drill into the repo's findings + scan history.

### Findings (`#/findings`)

Per-finding cards across the entire org. Each card shows:

- Severity badge + check ID + name
- Filename, line number, code excerpt
- AI assessment in an emerald-themed inline panel — confidence score,
  classification (real / likely-false-positive / needs-review),
  plain-English explanation
- Suggested unified-diff patch with syntax-highlighted +/- lines
  (when `--ai-fix` is enabled in the scanner)
- Two action buttons: "False positive" (feeds AI training set) and
  "Apply patch"

Demonstrates the AI moat in the surface where customers actually
feel it.

### Compliance (`#/compliance`)

Framework-control rollups. Pick PCI-DSS, SOC 2, ISO 27001, MiCA,
DORA, NIST CSF, or any of the 33 frameworks; see per-control pass/fail
status across all repos. The "Generate audit pack" button produces a
PDF + ZIP bundle mapped to the framework's control catalog.

This is the deliverable that justifies Pro/Enterprise pricing — the
auditor-ready handoff.

### Settings (`#/settings`)

Sub-pages: Organization (name, logo for branded PDFs, primary color),
Team (invite by email, roles: Owner / Admin / Auditor / Member),
Billing (Stripe-hosted subscription), License (regenerate, revoke),
API tokens (one-time-shown, scoped), Notifications (Slack webhook,
email digest, threshold alerts), Data export.

## How to navigate

Hash-routed SPA — every surface is reachable via a permalinkable URL:

- `https://app.preston-check.com/#/home`
- `https://app.preston-check.com/#/repos`
- `https://app.preston-check.com/#/findings`
- `https://app.preston-check.com/#/compliance`
- `https://app.preston-check.com/#/settings`

The left rail is sticky on every surface. Org switcher in the top
bar lets the operator (you, when impersonating) jump between
customer accounts; for actual customers it shows their org only.

## Source

`web/customer/` in the public repo:

```
web/customer/index.html         single-page app shell with five sections in DOM
web/customer/styles.css         design system layered on the landing-page tokens
web/customer/app.js             hash router (no innerHTML; safe DOM APIs only)
web/customer/functions/         Cloudflare Pages Functions (server-side)
  api/v1/telemetry/index.ts     telemetry ingest endpoint
web/customer/_routes.json       locks /api/* to Functions, no static fallback
```

## Hosted on

Cloudflare Pages, project name `preston-check-customer`. Auto-deploys
from `web/customer/` on every master push that touches the source.
Custom domain `app.preston-check.com` bound via the Pages dashboard.

## How to update

Edit any file under `web/customer/` and push to master. The
`customer-pages.yml` workflow auto-deploys within 60-90 seconds.

To preview locally:

```bash
cd web/customer
python3 -m http.server 8082
# open http://localhost:8082/
```

To deploy manually:

```bash
gh workflow run customer-pages.yml --repo preston-check/preston-check
```

## Production roadmap

Q3 2026 brings the four production wires that turn the skeleton into
a real product:

1. **Magic-link auth** — passwordless login via email PIN, same
   Cloudflare-Access-style mechanism the admin portal uses
2. **Stripe billing** — subscription tier selection, plan upgrades,
   self-serve cancellation, invoices
3. **Scan-result ingestion** — POST endpoint that accepts the
   scanner's report.json from a CI run, stores it under the customer's
   org, displays in /repos and /findings
4. **License issuance** — operator triggers a license issue from the
   Admin Portal; customer sees the new license in /settings and can
   download it as a `.license` file

Each of these is documented in `docs/portals-and-kpis.md` (Customer
Portal section) and on the build sequence in
`docs/commercial-roadmap.md`.

## Cross-links

- **User Manual**: `docs/manuals/user-manual.md`
- **Admin portal**: `docs/manuals/admin-portal.md`
- **Telemetry endpoint**: `docs/manuals/telemetry-endpoint.md` (lives on this same Pages project)
