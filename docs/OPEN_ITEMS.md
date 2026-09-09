# Open Items

Durable request queue. One row per incoming request, in the order received.
An item leaves this file only by being completed and deployed, or by Diego
explicitly dropping it. Blocked items move to the Blocked section and MUST name
the exact condition that would unblock them.

| # | Received | Request | Status |
|---|----------|---------|--------|
| 1 | 2026-09-06 | Failure alerts arriving for the last few days — find the failing workflow(s), diagnose the actual cause from run logs, fix, and verify. | DONE 2026-09-06 — three defects found; two fixed and verified at runtime, one merged awaiting its first live cycle (Blocked #2). Release run 34064649300 green; tap formula carries 4 bottles again. |
| 4 | 2026-09-06 | Build `quality-gate-test`: comprehensive acceptance test covering 100% of endpoints, webhooks, functionality and rendered front ends. Runnable ahead of every deployment; no deployment to production without it. | DONE 2026-09-06 — PR #878, master `3be6da49`. 117 assertions over 58 inventoried surfaces, 0 failures (run 34066269285). Enforcement proven live: pages.yml run 34066383807 shows `quality-gate → build → deploy`. |

| 9 | 2026-09-09 | Real Stripe + SES contract tests, so API compatibility is covered rather than only the requests this code builds. | IN PROGRESS — Diego approved 2026-09-09. Needs sandbox credentials as repo secrets; exact list requested from Diego this turn. |
| 8 | 2026-09-09 | Build and run the Docker image inside the quality gate, so a broken Dockerfile or entrypoint fails before publish. | IN PROGRESS — Diego approved 2026-09-09, accepting the ~2-4 min per-gate cost. |
| 7 | 2026-09-09 | Local Node < 22 blocks the Worker/licence/email/journey suites on Diego's machine. | IN PROGRESS — Diego approved 2026-09-09 for me to run `nvm install 24` (writes to ~/.nvm, outside the project wall; one-off approval). |
| 6 | 2026-09-09 | Tap pushes had no retry and could silently downgrade the formula. | DONE 2026-09-09 — `tools/tap-push.sh` replaces both push sites; retries with backoff, rebases on rejection, and refuses to publish a stale version (checked before committing, since the older push is a clean fast-forward when a newer release landed first). Verified against real git repos across four cases including the downgrade attempt. Master `4b681c8d`. |
| 5 | 2026-09-08 | "Are we at 100% coverage?" — audit the gate's real coverage against the product. | ANSWERED 2026-09-08 — no. 100% of a 59-surface inventory, but that inventory excludes licence generation, front-end interaction, SES/Resend delivery, the CLI/lib/checks, action.yml, install.sh, docker/ and ai-addon/. Written up in `docs/quality-gate-coverage.md`. Structural hole closed same day: `release.yml` now depends on `test.yml` (`inv.release-gated-on-cli-tests`). Remaining gaps OPEN below. |

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
and `.github/workflows/quality-gate.yml` deliberately pins 24. Locally the gate
needs `nvm install 24` — Diego's current Node is 20.20.2, which can run the
front-end and invariant suites but not the Worker suites.
