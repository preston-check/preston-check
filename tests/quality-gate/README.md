# quality-gate-test

The pre-deployment acceptance gate. Nothing reaches production without it.

```bash
./tests/quality-gate/quality-gate-test              # the full gate
./tests/quality-gate/quality-gate-test --only auth  # one suite (cannot gate a deploy)
```

Exit `0` means safe to deploy. Anything else means do not deploy.

## What it actually does

Every Worker is booted under the real `workerd` runtime via `wrangler dev
--local`, with real local D1 and KV — not hand-written fakes. Fakes are what
stop catching schema drift, SQL typos and binding-name mistakes, which is the
class of defect that otherwise only appears in production. Each suite then
drives the Worker over HTTP and, where a route is supposed to write something,
reads the row back out of D1 to prove the write landed rather than trusting a
`200`.

The Stripe webhook is exercised for every event type the Worker dispatches on,
each signed with a real HMAC-SHA256 signature built the way Stripe builds it,
plus signature rejection (missing, malformed, wrong secret) and replay
idempotency. A webhook suite that stubs out signature verification would pass
while the deployed Worker rejected every live event.

Front ends are loaded in a real headless Chromium, in the directory layout the
deploy workflow actually publishes — not the source tree. `web/admin/index.html`
ships as `out/index.html` with shared art under `out/landing/assets/`, so its
`../landing/assets/x.svg` clamps to `/landing/assets/x.svg`. Serving the source
tree makes those 404 in the test while production is fine, which is the wrong
way round for a gate. Each page is asserted to respond 200, raise no uncaught
exceptions, load every local asset, paint a non-trivial body, and render
specific visible text that disappears if the app's JS fails to initialise.

## Why it stays at 100%

`surface.json` is the inventory of every route, webhook event, page and
invariant. Three things must hold for the gate to pass:

1. every assertion passed;
2. every id in `surface.json` was actually asserted by some suite, and no suite
   asserted an id absent from the inventory;
3. `drift-check.mjs` independently re-derives the surface from the Worker
   sources and the deploy workflows, and agrees with `surface.json`.

(3) is what stops this decaying into a snapshot. Adding `POST /refund` to a
Worker, or a new `case 'invoice.voided':` to the webhook switch, fails the gate
until it is both inventoried and tested. The same check compares each front
end's staging list against the `cp` lines in its deploy workflow, so the gate
cannot end up rendering a layout that no longer ships.

## Why it cannot be quietly bypassed

`suites/invariants.mjs` asserts that all seven deploy workflows — `pages`,
`admin-pages`, `customer-pages`, `auth-deploy`, `billing-deploy`,
`telemetry-deploy` and `release` — call `quality-gate.yml` and that every job in
them depends on it, directly or transitively. Removing the gate from a deploy
workflow therefore fails the gate itself. It defends its own wiring.

Two further invariants: no live secrets committed (matching key *shapes*, not
bare prefixes, with `tests/fixtures/` and `corpus/` excluded because this repo
ships realistic fake credentials as scanner detection material), and
`STRIPE_API_BASE` absent from every deployed config.

## STRIPE_API_BASE

`workers/billing` reads an optional `STRIPE_API_BASE`, defaulting to
`https://api.stripe.com`. It exists solely so the gate can point the Worker at a
local mock and exercise the success paths of `/checkout`, `/billing-portal` and
`/license`, which are otherwise unreachable without live Stripe credentials.
Production behaviour is unchanged. `inv.no-stripe-api-base-in-deployed-config`
fails the gate if it ever appears in a `wrangler.toml` or deploy workflow, so
the test seam cannot become a production hole.

## Requirements

Node >= 22. The gate runs each Worker under `wrangler`; wrangler >= 4.87
requires Node >= 22, and earlier wrangler refuses the `compatibility_date`
declared in `workers/*/wrangler.toml`, so an older Node cannot run this at all.
The entry script checks for a usable Node (including nvm and Homebrew installs)
and explains what to install rather than failing with a wrangler stack trace.

Rendered front-end checks need Playwright:

```bash
npm install --no-save playwright@1.56.0 && npx playwright install chromium
```

If Playwright is missing the front-end surfaces are recorded as **failures**,
never skips — a gate that silently drops half its scope is worse than no gate.

CI installs both and runs on Node 24 (`.github/workflows/quality-gate.yml`).
