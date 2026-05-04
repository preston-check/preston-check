---
title: "Preston-Check Public Website — Design Spec"
subtitle: "Visual system, iconography, and content architecture for preston-check.com"
author: "Preston-Check Maintainers"
date: "2026-05-04"
---

# Public Website Design Spec

The landing page lives at `web/landing/`. It is a static, single-file
implementation: one `index.html`, one `styles.css`, an `assets/` folder
for the brand mark and watermark, and an `icons/` folder for the
proprietary icon set. Zero CDN dependencies, zero third-party icon
libraries, zero JavaScript at launch. Everything renders from disk on a
plain HTTP server.

## Brand fundamentals

### Name and persona

Preston-Check. Hyphen-cased. Wordmark uses a middle-dot separator
("Preston·Check") in display contexts where the hyphen reads heavy.
Persona: rigorous, fintech-grade, friendly-but-serious. The product is
an audit tool — confidence and calm beat hype.

### Color tokens

| Token        | Hex      | Usage                                          |
|--------------|----------|------------------------------------------------|
| `--ink`      | `#0B1F3A`| Deep navy. Primary text, brand mark, dark sections. |
| `--paper`    | `#FFFFFF`| Default surface.                               |
| `--paper-2`  | `#F8FAFC`| Raised surface (cards, alt sections).          |
| `--rule`     | `#E2E8F0`| Hairlines, dividers, default borders.          |
| `--mute`     | `#475569`| Secondary text (body copy in muted contexts).  |
| `--mute-2`   | `#94A3B8`| Tertiary text (captions, eyebrow).             |
| `--accent`   | `#10B981`| **Brand emerald.** Score, PASS, brand accents. |
| `--accent-2` | `#2563EB`| Action blue. Used sparingly for non-brand links. |
| `--warn`     | `#F59E0B`| WARN findings.                                 |
| `--bad`      | `#DC2626`| FAIL / critical.                               |

Single-axis brand color (emerald). Action blue is restricted to inline
text links so the page reads as a two-color system at glance. The deep
navy carries the heavy aesthetic load — backgrounds, text, the brand
mark — which is intentional: navy + emerald is the financial-services
trust palette without being literally bank-blue.

### Typography

System-stacked. No web font loads.

* **Headings** — `ui-serif, Georgia, "Times New Roman", serif`. The
  serif at large display sizes signals editorial seriousness. Modern
  Mac/iOS users get New York; modern Windows users get Cambria;
  fallback is Georgia. All four are quality serifs.
* **Body** — `ui-sans-serif, system-ui, -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif`.
  Legible at 18px body, scales gracefully.
* **Mono** — `ui-monospace, "SF Mono", Menlo, Consolas, monospace`. For
  terminal blocks and code excerpts.

Modular type scale at 1.250 (major third) anchored on 18px body:
14 / 18 / 22 / 28 / 36 / 44 / 56. Hero h1 sits at 56px desktop, 40px
mobile. Body line-height is 1.6. Headings tighter at 1.05 (h1) to 1.3
(h3) for the editorial cadence.

### Iconography — proprietary set

Sixteen custom SVG icons live at `web/landing/icons/`. Every icon is:

* **24×24 viewBox**, with all artwork inside the visible area.
* **1.6px stroke**, `currentColor`, `stroke-linecap="round"`,
  `stroke-linejoin="round"`. Inherits theme color from CSS.
* **No fill** unless intentionally solid for emphasis (the brand
  mark uses an emerald-filled facet on top of the navy shield).
* **Geometric and slightly rounded.** Avoids the over-smooth cartoony
  look of consumer-app sets and avoids the wireframe austerity of
  open-source defaults like Heroicons.
* **Carries the brand "diamond facet"** motif where applicable —
  scan, badge, chain, contract, portal all reference the same internal
  diamond shape that lives in the logomark.

Catalog:

| File             | Concept                                     |
|------------------|---------------------------------------------|
| `shield.svg`     | Brand mark (also used as bullet asset).     |
| `diamond.svg`    | Pure brand motif — tilted square + facet.   |
| `scan.svg`       | Scan / search.                              |
| `patch.svg`      | Auto-fix / wrench.                          |
| `sparkle.svg`    | AI augmentation.                            |
| `lock.svg`       | Privacy / airgap.                           |
| `badge.svg`      | Compliance evidence / rosette.              |
| `graph.svg`      | Telemetry / score / trend.                  |
| `terminal.svg`   | CLI / command-line.                         |
| `book.svg`       | Catalog / docs.                             |
| `chain.svg`      | Cross-chain / interlocked.                  |
| `clock.svg`      | Timelock / time-based control.              |
| `puzzle.svg`     | Integrations / fit-together.                |
| `portal.svg`     | Customer / admin portal.                    |
| `threat.svg`     | Threat intel / radar.                       |
| `contract.svg`   | Smart contract / scroll.                    |

The set is deliberately small. Pages that need an icon for a concept
not in the set get a new icon authored to fit the family — they do
not pull from third-party libraries.

### Brand mark (logomark + wordmark)

The logomark composes three layers:

1. A **navy shield** outline (`#0B1F3A`) — the security-tool semantic.
2. An **emerald diamond** with an internal facet — the brand motif
   that recurs across the icon set.
3. A **white check tick** across the inner facet — the "Check" in
   Preston-Check, drawn boldly enough to read at favicon size.

The wordmark renders the logomark at 0.66× scale plus
"Preston·Check" in a 26px serif. The middle dot is emerald to echo
the diamond. SVG-native text is used (not an outlined path) so the
wordmark scales without aliasing and stays editable.

The hero **score badge** (`assets/score-badge.svg`) is a 280×280
ring with a calibrated 87% emerald arc and the letter grade "A−" in
a 120px serif. It demonstrates the score-as-headline UX pattern in
the very first viewport — a developer landing on the page sees what
the scanner produces before reading any copy.

## Page architecture

The landing page is a long-scroll, eight-section narrative. Each
section serves a single rhetorical purpose; transitions are driven by
1px hairline rules rather than dramatic background flips, so the page
reads as one continuous artifact rather than a stack of cards.

1. **Hero** — name, value proposition, instant install command, hero
   score badge. Goal: the visitor knows in seven seconds what this
   tool does and how to start using it.
2. **Pillars** — three commitments that differentiate Preston-Check
   from generic scanners (open scanner / AI-augmented / privacy
   first). Goal: address the three competing-tool objections at once.
3. **Terminal** — verbatim sample output. Goal: developers who skip
   marketing copy and want to see the thing actually working.
4. **Features grid** — nine concrete capabilities, each with a custom
   icon and a one-sentence description. Goal: scannable depth.
5. **Frameworks** — full pill-strip of all 33 frameworks, with the
   five most fintech-relevant emphasized in emerald. Goal: convince
   the compliance-minded buyer that the catalog is real.
6. **Pricing** — three-tier table (Free / Pro / Enterprise). Goal:
   honest pricing without dark patterns; "Most fintechs" ribbon on
   the Pro tier where the conversion is.
7. **Origin story** — the Preston Braswell narrative + four headline
   stats. Goal: a story that makes the tool feel earned. Stories
   travel further than feature lists.
8. **Final CTA + footer** — one more clear ask, plus a footer with
   product / resources / company columns and a colophon noting the
   proprietary icon set.

## Content tone

Sentences with subjects and verbs. No headline-speak. No hero copy
that reads "Empower your DevSecOps to harness the power of AI-driven
security at scale" — that style mistakes vagueness for credibility.

The hero h1 is one declarative sentence with a strong verb and a
specific object: *"Pre-deployment security audits for fintech that
**actually catch the bugs that ship money to attackers**."* That is
the tool's job. The rest of the page proves it.

## Deployment

Three options, in order of preference:

1. **Cloudflare Pages** — point at `web/landing/` as the build dir.
   Free tier, global edge, instant cache invalidation. Wire DNS for
   `preston-check.com` apex + `www`.
2. **GitHub Pages** — `web/landing/` as the source folder. Slower
   cache invalidation, but free and zero infrastructure.
3. **Static-hosting any provider** — Netlify, Vercel, S3+CloudFront,
   Bunny CDN. The build is literally three folders of static files.

For previewing locally:

```bash
cd web/landing && python3 -m http.server 8080
# open http://localhost:8080/
```

No build step required. No bundler. No package.json. The whole site
is reviewable in a single browser tab and git diff is human-readable.

## Future surfaces

Pages not yet built that should follow the same design system:

* **`/docs`** — auto-generated from the markdown in `docs/`.
  Recommended renderer: Cloudflare Pages + a small markdown-to-HTML
  step (`pandoc -t html5 --template=docs.html`).
* **`/changelog`** — render `CHANGELOG.md` directly into a styled
  page. Same template as docs.
* **`/state-of-fintech-security`** — annual report landing.
  Headline statistics in a hero band, then the report as embedded PDF
  + extracted highlights.
* **`/blog`** — for engineering and security-research posts. Same
  visual system, single-column long-form layout.

The design system in `styles.css` is the contract. Every additional
page must consume the same tokens and reuse the same icon set. New
concepts get new proprietary icons authored to fit the family — never
imported.
