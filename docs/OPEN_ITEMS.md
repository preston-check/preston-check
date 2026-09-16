# Open Items

Durable request queue. One row per incoming request, in the order received.
An item leaves this file only by being completed and deployed, or by Diego
explicitly dropping it. Blocked items move to the Blocked section and MUST name
the exact condition that would unblock them.

| # | Received | Request | Status |
|---|----------|---------|--------|
| 1 | 2026-09-06 | Failure alerts arriving for the last few days — find the failing workflow(s), diagnose the actual cause from run logs, fix, and verify. | DONE 2026-09-06 — three defects found; two fixed and verified at runtime, one merged awaiting its first live cycle (Blocked #2). Release run 34064649300 green; tap formula carries 4 bottles again. |
| 4 | 2026-09-06 | Build `quality-gate-test`: comprehensive acceptance test covering 100% of endpoints, webhooks, functionality and rendered front ends. Runnable ahead of every deployment; no deployment to production without it. | DONE 2026-09-06 — PR #878, master `3be6da49`. 117 assertions over 58 inventoried surfaces, 0 failures (run 34066269285). Enforcement proven live: pages.yml run 34066383807 shows `quality-gate → build → deploy`. |

| 9 | 2026-09-09 | Real Stripe + SES contract tests. | SES DONE, STRIPE BLOCKED — `tests/contract/run.mjs` + `contract-checks.yml`. SES verified against real AWS in CI run 34316172377 (signed v2 send accepted, MessageId returned), using existing credentials. Stripe needs repo secret `STRIPE_TEST_SECRET_KEY` (an `sk_test_` key). Daily cron is commented out until it exists; I enable it in the same change that adds the secret. |
| 8 | 2026-09-09 | Build and run the Docker image inside the quality gate. | DONE 2026-09-09 — `suites/docker.mjs`, master `48fe9e5c`. Builds the image, runs `--help`, asserts non-root from inside the container via `id -un`, runs a real scan over a mounted tree, and checks the result is populated. 6/6 locally. Inventory 75. |
| 7 | 2026-09-09 | Local Node < 22 blocked most of the gate on Diego's machine. | DONE 2026-09-09 — Node 24.21.0 installed via nvm. Running it end to end locally for the first time exposed two real defects (PATH not carrying the chosen Node to `npx wrangler`; a second wrangler process killing the dev server with ECONNRESET). Both fixed in master `bf33a45f`; full gate now passes locally, 170/170 across 74 surfaces. |
| 6 | 2026-09-09 | Tap pushes had no retry and could silently downgrade the formula. | DONE 2026-09-09 — `tools/tap-push.sh` replaces both push sites; retries with backoff, rebases on rejection, and refuses to publish a stale version (checked before committing, since the older push is a clean fast-forward when a newer release landed first). Verified against real git repos across four cases including the downgrade attempt. Master `4b681c8d`. |
| 5 | 2026-09-08 | "Are we at 100% coverage?" — audit the gate's real coverage against the product. | ANSWERED 2026-09-08 — no. 100% of a 59-surface inventory, but that inventory excludes licence generation, front-end interaction, SES/Resend delivery, the CLI/lib/checks, action.yml, install.sh, docker/ and ai-addon/. Written up in `docs/quality-gate-coverage.md`. Structural hole closed same day: `release.yml` now depends on `test.yml` (`inv.release-gated-on-cli-tests`). Remaining gaps OPEN below. |

| 10 | 2026-09-14 | Watchdog: Release #486–#490 all failed (2026-09-13 13:03 → 2026-09-14 08:26). Diagnose from run logs, fix, verify. | DONE 2026-09-16 — master `9645f6fd`, Release #499 green. The fix sat uncommitted from 2026-09-14 until today; meanwhile the trust refusal was fixed upstream (#498 logs `Trusted formula …` on every leg with no trust call on master), so `brew trust` now ships as non-fatal cover rather than a dependency. The docs half of it — `brew trust` in every install instruction, and the corrected `preston-check/tap/preston-check` tap path — did matter and is live, held by `inv.brew-tap-trusted-before-use`. The expected bottle count is 3, not 4: see item 13. |
| 11 | 2026-09-14 | (found while fixing #10) Quality-gate harness aborts the ENTIRE run when one `req()` exceeds its 15s timeout. Observed once under four concurrent wrangler servers: the `get` suite raised `AbortError`, 27 surfaces then reported as "never asserted" and the gate said FAILED. Re-run was 177/177, so it is a flake — but a flake that blocks all 7 deploy workflows and produces a misleading coverage report. | OPEN — needs a decision on failure isolation, see the question posed to Diego 2026-09-14. |
| 12 | 2026-09-14 | (found while fixing #10) `docs/_rendered/` is committed but never rebuilt in CI, so it silently drifts from `docs/`. `operator-runbook`, `architecture`, `language-coverage` and `index` were already stale before this session. | OPEN — the rendered manuals are what customers receive; nothing currently detects the drift. |
| 13 | 2026-09-16 | Watchdog alert: Release #494–#498 failing (2026-09-15 → 2026-09-16). Diagnose from run logs, fix, verify. | DONE 2026-09-16 — master `9645f6fd`. Release #499 (run 35096795374) green: 3/3 bottle legs, `update-tap` success logging `Updated formula: 3 bottle(s) — arm64_tahoe, arm64_sequoia, x86_64_linux`. The published tap formula for v1.8.469 carries exactly those three, and the downloaded `arm64_tahoe` bottle hashes to `dfdc79a5…`, matching the formula. Detail below. |

## Item 10 — the three defects behind Releases #486–#490

Homebrew 6.0 will not load a formula from a non-official tap until that tap is
trusted (`$HOMEBREW_REQUIRE_TAP_TRUST`, default true). It surfaces the refusal
as `Cannot tap preston-check/tap: invalid syntax in tap!`, preceded by one
`Invalid formula (<os_tag>)` line per bottle tag. That message names neither
trust nor the cause and reads like broken Ruby in our own formula. It is not.

1. **Every bottle leg failed** on all four platforms from v1.8.456 onwards,
   because `release.yml` tapped without trusting. Fixed: `brew trust --tap
   preston-check/tap` before `brew tap`. Order matters — the tap is the step
   being refused, so trusting afterwards still fails.

2. **`update-tap` went green while publishing a bottle-less formula.** The
   zero-bottle guard printed `::error::` and nothing else; an annotation does
   not change the exit code. v1.8.457–v1.8.460 all shipped with no `bottle do`
   block, so `brew install` built from source on every platform. Fixed:
   `raise SystemExit(1)`.

3. **Every published install instruction was broken for end users**, not just
   CI — the trust refusal hits anyone on Homebrew 6.0+. `brew trust` added to
   README, landing page, getting-started, user manual, distribution, the tap
   manual, the selling sheet and the sales playbook, plus the source formula
   header. The sales material additionally pointed at
   `preston-check/preston-check/preston-check`, a tap that has never existed;
   corrected to `preston-check/tap/preston-check`.

Mechanism: `inv.brew-tap-trusted-before-use` in the quality gate. It greps every
tracked file that tells a reader to tap/install from our tap and fails unless
that file also mentions `brew trust`, and separately asserts that `release.yml`
trusts *before* tapping. Both failure modes were provoked and observed failing.
Records and generated output (`CHANGELOG.md`, `docs/sessions/`,
`docs/_rendered/`, `OPEN_ITEMS.md`) are excluded so history is not rewritten to
satisfy a check about present-day instructions.

## Item 13 — Releases #494–#498, and why nothing went red when a platform vanished

Only one leg failed: `bottle (macos-14, arm64_sonoma)`, with "The following
formulae cannot be installed from bottles and must be built from source —
readline, bash and coreutils". Homebrew has moved ARM macOS 11–14 to support
tier 3, so neither Preston-Check nor its dependencies get Sonoma bottles, and
`--build-bottle` refuses rather than building them. The leg cannot succeed, and
a forced source build would produce a bottle no macOS 14 user could install
anyway — their `brew install` still needs those same dependencies.

1. **macOS 14 leg removed** from the matrix, as the Intel leg was on 2026-09-06
   for the identical reason. Tier 3 users take `install.sh`, which is POSIX sh
   and needs no Homebrew dependencies. That path is now stated wherever
   Homebrew is offered — README, getting-started, user manual, tap manual, the
   formula caveats, and the landing page, which until now handed a tier 3
   visitor a command that could only fail, with no alternative on the page.

2. **The guard counted instead of comparing.** It failed only when *zero*
   bottles existed, so v1.8.465–v1.8.468 published three of four platforms with
   every job green — silent platform loss again, in a shape the Intel fix did
   not cover. `release.yml` now declares `EXPECTED_BOTTLE_TAGS` once at workflow
   level; the matrix builds exactly those, and `update-tap` fails when any is
   missing from the published formula. The failure is raised *after* the tap
   push: publishing three bottles and going red beats aborting and leaving the
   tap bottle-less on every platform.

3. **`brew trust` (item 10) resolved upstream.** Release #498 shows every leg
   logging `Trusted formula preston-check/tap/preston-check` right after
   tapping, with no trust call on master at all; the runners were fetching
   homebrew/brew branches `trust-bare-tap-argv` and
   `trust-normalise-tap-reference` in that same run. The call still ships as
   cover against a re-tightening, but non-fatal — a defensive call must not be
   able to break a release.

Mechanism: `inv.bottle-tags-match-matrix` parses `release.yml` and fails if the
matrix legs and `EXPECTED_BOTTLE_TAGS` disagree in either direction, or if
`update-tap` stops reading the declaration. All three were provoked and
observed failing. The shipped `update-tap` script was extracted and executed
against a fixture tap for all-present, one-missing and none-present.

## Blocked

| # | Item | Unblocks when |
|---|------|---------------|
| 2 | ~~Promotion stalled 2026-09-06 → 2026-09-08~~ | **DONE 2026-09-08.** Fix on master `d6ed898d`: the orchestrate job approves its own branch's pending runs before waiting. Proven live on PR #883's own cycle — `Approve the promotion PR's pending checks: success`, log `approved 4 pending run(s)`. Backlog fully drained: #879–#883 all merged (`a33ce3fa`, `398af421`, `3d42e66c`, `d81556df`, `36f58795`). No open promotion PRs. |
| 3 | ~~Watchdog alerts from the pre-fix Release failures~~ | **DONE 2026-09-08.** Original cause aged out; the stuck-promotion alert cleared once the backlog drained. The watchdog correctly detected the regression while it existed. |

## Coverage gaps — CLOSED 2026-09-08

Diego asked for all four; all four are closed and verified in CI
(run 34232259442: **170 passed, 0 failed, 74 surfaces**).
Current scope and its deliberate limits: `docs/quality-gate-coverage.md`.

| Gap | Closed by |
|-----|-----------|
| Licence generation never executed | Throwaway Ed25519 key per run; the issued licence is verified by `lib/license.sh` — the CLI's own openssl verifier — and a tampered payload must be rejected |
| Front-end interaction never driven | `suites/flow.mjs` drives the sign-in funnel in a browser against real Workers: login screen → e-mail → code step → verify → signed-in → token persisted |
| SES SigV4 never run | `lib/ses.mjs` independently re-derives the signature from the received request; the request is still signed for the real SES host |
| CLI / lib/ / checks outside the gate | `suites/cli.mjs`: run-tests.sh, metadata evidence, corpus size + bash validity, fixture scans, airgapped self-scan, `--framework` |
| `action.yml`, `install.sh`, `docker/`, `ai-addon/` | `suites/packaging.mjs`, including a non-root `USER` assertion on the image |

## Standing rule (Diego, 2026-09-09)

Drive every task to completion. A defect found in this code is mine to fix,
whoever introduced it — "not my problem" is never acceptable, and logging a
defect is not resolving it. Where something genuinely cannot be resolved inside
the session (permission, credential, account setting, a decision only Diego can
make), ASK Diego in that same turn, naming exactly what is needed. Do not park
it on a watch-list. Full text: `memory/feedback_drive_to_completion.md`.

Applied immediately: the `update-tap` retry below was parked on this list last
turn and has now been fixed rather than watched.

## Notes for the next session

The quality gate needs **Node >= 22**; this repo's other workflows pin Node 20,
and `.github/workflows/quality-gate.yml` deliberately pins 24. Node 24.21.0 is
now installed locally via nvm (2026-09-09) and the full gate passes on Diego's
machine — `./tests/quality-gate/quality-gate-test` selects a suitable Node
itself, including from `~/.nvm`, so no `nvm use` is needed first.

The gate also needs a reachable Docker daemon (for `suites/docker.mjs`) and
Playwright with chromium (`npm install --no-save playwright@1.56.0 && npx
playwright install chromium`). Both are present locally; both are treated as
failures rather than skips if missing.
