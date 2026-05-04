# Admin Portal — clickable skeleton

Static HTML/CSS/JS skeleton of the operator portal specced in
[`docs/portals-and-kpis.md`](../../docs/portals-and-kpis.md). Eight
surfaces (Customers, Sales, Revenue, Users, Licenses, Threat-Intel,
Support, System), realistic mock data, full visual polish, deployable
to Cloudflare Pages or Vercel as-is.

This is the **clickable shell**, not the production app. It demonstrates
surface, navigation, and information architecture for design partners
and investor demos. The production version replaces the inline mock
data with API calls to `api.preston-check.com` and adds auth, billing,
and license-issuance wiring.

## What's in here

* `index.html` — single-page app shell with all eight sections in DOM,
  hash-routed, so `https://admin.preston-check.com/#/revenue` opens
  directly to the Revenue page.
* `styles.css` — design tokens shared with the public landing page,
  plus operator-portal primitives (left rail, top bar, KPI tiles,
  dense data tables, kanban, cohort heatmap, system health board).
* `app.js` — hash router and customer-table renderer using DOM APIs.
  No `innerHTML` on data, no `eval`, no third-party JS.
* `../landing/icons/` — 23 proprietary SVG icons shared between the
  landing page and admin (the same visual language).
* `../landing/assets/` — logomark, wordmark, score badge,
  diamond watermark.

## Preview locally

```bash
cd web/admin
python3 -m http.server 8081
# open http://localhost:8081/
```

Hash routes:

* `#/customers` — customer master list (default)
* `#/sales` — pipeline kanban (Lead → Qualified → Demo → Trial → Closed-won)
* `#/revenue` — MRR / ARR / NRR + trailing-12mo chart + waterfall + cohort heatmap
* `#/users` — every user across every org with role + 2FA + last-login
* `#/licenses` — issued license table with Ed25519 fingerprints
* `#/threat-intel` — weekly NVD draft triage queue
* `#/support` — inbox of customer tickets with SLA timers
* `#/system` — operational health + build attestation panel

## Deployment

Same channels as the landing page. Cloudflare Pages is the recommended
target — point a project at `web/admin/` and bind to
`admin.preston-check.com`. The Cloudflare Access policy in front of
admin.* should allow only the operator's own GitHub identity (and a
backup recovery contact).

## What's mocked vs. real

Everything is mocked. There is no API, no auth, no Stripe webhook, no
license-issuance flow. The hash-routed shell exists to make the
information architecture concrete and reviewable before the production
build sequence (Q4 2026 per `docs/commercial-roadmap.md`) starts.

## Visual system

Same `--ink`, `--paper`, `--accent` color tokens as the landing page;
same proprietary icon family; same serif headings + system-stack body.
The operator portal is denser than marketing (14px body vs 18px,
240px side rail, 56px top bar) but reads as the same product family at
a glance.
