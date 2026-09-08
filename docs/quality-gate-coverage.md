# Quality gate — coverage

Updated 2026-09-08, after closing all four gaps identified in the first audit.

The gate reports "all 74 inventoried surfaces asserted". That number is a
computed reconciliation, not a claim: the run fails unless every id in
`surface.json` was asserted by some suite, no suite asserted an uninventoried
id, and `drift-check.mjs` independently re-derives the surface from the sources
and agrees.

## What is covered

**Workers.** Every HTTP route of all four Workers, exercised against the real
`workerd` runtime with real local D1 and KV: 18 routes on auth, 18 on billing,
6 on telemetry, 2 on get. Where a route writes, the row is read back out of D1
rather than trusting a 200.

**Stripe webhook.** All seven dispatched event types with genuine HMAC-SHA256
signatures, plus rejection of missing, malformed and wrong-secret signatures,
and replay idempotency asserted down to the stored row count.

**Licence issuance.** A throwaway Ed25519 pair is generated per run so
`generateLicenseFile()` actually executes. The licence the Worker issues is
then verified by `lib/license.sh` — the CLI's own openssl-based verifier —
rather than by a reimplementation, so the assertion covers the contract between
the two sides. A tampered payload is asserted to be rejected, which is what
stops the check passing against a verifier that never verifies.

**E-mail delivery.** The auth Worker's hand-rolled SigV4 signer is exercised
against a SES mock that independently re-derives the signature from the request
it received. The request is still signed for the real SES host, so the
signature under test is byte-identical to production's.

**Customer journey.** The sign-in funnel is driven in a real browser against
real Workers: land on the login screen, submit an address, advance to the code
step, read the issued code out of KV, verify it, and confirm the signed-in
transition and that the session token is persisted.

**Front ends.** Six pages rendered in headless Chromium in the layout the
deploy workflow actually publishes, asserted for status, uncaught exceptions,
local asset integrity, a non-trivial painted body, and visible text that
disappears if the app's JS fails to initialise.

**The shipped CLI.** `--help`, the full `tests/run-tests.sh` harness, evidence
that the check-metadata suite actually ran, corpus size and bash validity
across all check scripts, scans of the known-bad and known-good fixtures, the
airgapped free-tier self-scan, and `--framework` filtering.

**Packaging.** `action.yml` parses and declares a name, a runner and inputs,
with its referenced entrypoint present; `install.sh` parses, is shellcheck-clean,
sets a failure mode and resolves a download source; the Dockerfile declares a
base image, an entrypoint and a non-root `USER`, and its entrypoint script
parses; every shell and JSON asset under `ai-addon/` parses.

**Invariants.** No test-only API seam (`STRIPE_API_BASE`, `SES_API_BASE`) in a
deployed config; no live secrets committed; all seven deploy workflows depend
on the gate; and `release.yml` additionally depends on the CLI tests, because
this gate does not ship what a release ships.

## Known limits

These are deliberate, not oversights.

The Docker image is linted rather than built and run — a multi-minute build in
a pre-deploy gate gets skipped, and a skipped check is not a check.

The scanner is asserted to run to completion on the fixtures rather than to
produce an exact finding set; per-check detection accuracy is the corpus TPR/FPR
job, not this gate's.

Stripe and SES are exercised through mocks. Real API compatibility is not
covered, only the request this code constructs and the responses it handles.

`--only <suite>` skips coverage reconciliation and prints a warning; such a run
cannot gate a deploy.
