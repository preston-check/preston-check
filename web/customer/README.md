# Customer Portal — clickable skeleton

Static HTML/CSS/JS skeleton of the customer portal specced in
[`docs/portals-and-kpis.md`](../../docs/portals-and-kpis.md). Five
surfaces (Home, Repos, Findings, Compliance, Settings), realistic
mock data scoped to a single org (Helios Banking, Enterprise tier),
full visual polish, deployable to Cloudflare Pages or any static
host.

This is the **clickable shell**, not the production app. The
production version replaces the inline mock data with API calls to
`api.preston-check.com`, adds magic-link or SSO auth, wires Stripe
billing, and adds the live-CI scan-result-upload endpoint.

## What's in here

* `index.html` — single-page app shell with all five sections in DOM,
  hash-routed.
* `styles.css` — design tokens shared with the public landing page,
  plus customer-facing surfaces (hero score panel, score chip,
  finding cards with AI assessment + suggested patch, framework
  rollup tiles, settings form rows).
* `app.js` — hash router. No `innerHTML` on data; no third-party JS.
* `../landing/icons/` — the same proprietary 23-icon family used
  across landing + admin + customer.
* `../landing/assets/` — logomark, wordmark, score badge,
  diamond watermark.

## Preview locally

```bash
cd web/customer
python3 -m http.server 8082
# open http://localhost:8082/
```

Hash routes:

* `#/home` — score hero, top critical findings, framework coverage rollup
* `#/repos` — connected-repository list with score chips and 30d trends
* `#/findings` — per-finding view with AI assessment + diff patches
* `#/compliance` — framework-control rollups + evidence bundle generator
* `#/settings` — organization, team, billing, license, API tokens

## Deployment

Same channel as the admin portal. Cloudflare Pages is the recommended
target — point a project at `web/customer/` and bind to
`app.preston-check.com`. The Cloudflare Access policy in front is
optional for the customer portal (paying customers should be able to
authenticate themselves via magic link or SSO), but the production
version must add real authentication.

For the skeleton phase, this directory deploys publicly via the same
GitHub Pages workflow if `pages.yml` is extended to include
`web/customer/` under `/customer/`.

## What's mocked vs. real

Everything is mocked. There is no API, no auth, no Stripe, no real
scan upload. The hash-routed shell exists to make the customer
information architecture concrete and reviewable before the
production build sequence (Q3 2026 per `docs/commercial-roadmap.md`)
starts.

## Visual system

Reuses the landing-page design tokens — same `--ink` navy, same
emerald `--accent`, same serif headings paired with system sans body,
same proprietary icon family. The customer portal leans more emerald
than the admin (success-weighted, since the audience is the customer
viewing their own posture) and leads with the score badge as the hero
on the home page — that's the score-as-headline UX pattern from the
moat strategy doc made concrete.
