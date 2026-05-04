---
title: "Public Landing Page Manual"
audience: "operator, content contributors"
date: "2026-05-04"
---

# Public Landing Page

The marketing surface and the first impression every prospective
customer, partner, or journalist gets.

## URL

`https://preston-check.com/`

Mirror at `https://preston-check.github.io/preston-check/` (always
reachable even if the custom domain has a cert issue).

## What it is

A static, single-page, long-scroll narrative. Eight sections: hero with
score-badge mock, three pillars, terminal demo, nine-feature grid,
33-framework pill strip, three-tier pricing table, origin story with
stats, final CTA + footer.

Zero JavaScript at launch. Zero CDN dependencies. Renders entirely
from disk on a plain HTTP server. Loads under 50KB total.

## Hosted on

GitHub Pages. The custom domain `preston-check.com` is bound via a
CNAME file inside the deploy artifact + apex A records pointing at
GitHub Pages IPs in Route 53.

## Source

`web/landing/` in the public repo:

```
web/landing/index.html         single-page narrative
web/landing/styles.css         design system (color tokens, type scale, components)
web/landing/icons/             16 proprietary SVG icons (24x24, 1.6px stroke, currentColor)
web/landing/assets/            logomark, wordmark, score badge, diamond watermark
web/landing/CNAME              "preston-check.com" — Pages picks this up
```

## How to update

Edit `web/landing/index.html` (or styles.css, icons/, assets/) and push
to master. The `pages.yml` workflow auto-deploys on every push that
touches `web/landing/**`. Site updates within 60-90 seconds of merge.

To preview locally:

```bash
cd web/landing
python3 -m http.server 8080
# open http://localhost:8080/
```

## Design system

Documented in detail at `docs/website-design.md`. Three rules:

1. **Reuse the design tokens** from `styles.css` (--ink, --paper, --accent
   etc.) — never introduce a new color
2. **New icons get drawn from scratch** in the same style (24x24, 1.6px
   stroke, currentColor, recurring diamond-facet motif) — never import
   from a third-party library
3. **Editorial tone** — declarative sentences with subjects and verbs,
   no headline-speak, no marketing-fluff superlatives

## When to update

- New product feature ships → add to the nine-feature grid
- Pricing tier changes → update the pricing table (and propagate to
  the customer portal's Settings → Billing surface)
- New framework added → append to the framework pill strip
- Annual State of Fintech Security report ships → header banner
  linking to it for the first 30 days

## Analytics

Cloudflare Web Analytics (privacy-respecting, no cookies) — not yet
enabled. To enable: Cloudflare dashboard → Web Analytics → add
`preston-check.com` as a site, paste the resulting snippet into
index.html before `</body>`. Ten minutes to wire.

## Cross-links

- **Customer portal**: `https://app.preston-check.com/`
- **Admin portal** (operator only): `https://admin.preston-check.com/`
- **Source**: `https://github.com/preston-check/preston-check`
