# Quality gate — what is and is not covered

Written 2026-09-08 in answer to "are we at 100% coverage?".

The honest answer is **no, not of the product**. The gate reports "all 59
inventoried surfaces asserted", and that is true — but it is 100% of a defined
inventory, and that inventory is narrower than the product. This file records
the difference so the number is never mistaken for something it is not.

## What the gate does cover, fully

Every HTTP route of all four Workers, exercised against the real `workerd`
runtime with real local D1 and KV: 17 routes on auth, 17 on billing, 6 on
telemetry, 2 on get. Every one of the seven Stripe webhook event types the
billing Worker dispatches on, each with a genuine HMAC signature, plus
signature rejection and replay idempotency. Six front-end pages, loaded in
headless Chromium in the layout the deploy workflow actually publishes. Four
deployment invariants.

Within that scope the coverage is real: assertions read rows back out of D1
rather than trusting a 200, and the count is reconciled against the inventory
with an independent drift check.

## What is NOT covered

**License generation.** `LICENSE_SIGNING_KEY` is never set during a gate run,
so `generateLicenseFile()` and its Ed25519 signing never execute. Only the
rejection paths of `/license` are asserted. The artefact a paying customer
actually receives on completing checkout is untested. This is the most
commercially significant gap.

**Front-end behaviour.** 534 lines across `web/customer/app.js` and
`web/admin/app.js` — hash routing, settings tabs, token storage, `fetchMe`,
`requestCode`, `verifyCode`, checkout and licence download — are never driven.
The suite asserts initial render, absence of uncaught exceptions, asset
integrity and visible text. No click, no form submission, no sign-in flow.

**E-mail delivery.** The SES SigV4 path and the Resend fallback in the auth
Worker never run, because no credentials are present in a gate run; delivery
always takes the "manual" branch. The SigV4 signing implementation is
hand-rolled and entirely untested.

**The CLI itself.** The 703-line entrypoint, 1058 lines of `lib/`, and 1146
checks are not touched by any gate suite. They are covered separately by the
`Tests` workflow (lib tests, self-scan, framework filter). As of 2026-09-08
`release.yml` depends on that workflow, so a release is no longer gated purely
on code it does not ship — but the gate itself still does not exercise the
scanner.

**Unexercised entirely.** `action.yml`, `install.sh`, `docker/`, and the 38
files under `ai-addon/`.

## Where the boundary sits

The gate answers "will the hosted services and pages work when deployed". It
does not yet answer "will the product work for a customer end to end" — that
would need the licence path, the sign-in flow driven through the browser, and
the scanner itself under the same roof.
