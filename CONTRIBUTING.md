# Contributing to Preston-Check

Preston-Check is community-grown. New checks come from people who have seen
new attack patterns in the wild, identified compliance gaps, or noticed
classes of vulnerabilities that the existing catalog misses. This document
describes how to contribute, what gates exist, and what the trust tiers mean.

## Trust tiers

Checks live in one of four locations, and the location determines the trust
tier. The runner derives trust tier from the path, not from declared metadata.
This prevents contributors from claiming a higher tier than they have earned.

| Location | Trust tier | Runs by default? | How to author |
|---|---|---|---|
| `checks/core/` | core | yes | Maintainer-authored only |
| `checks/community/verified/` | verified | yes | Promoted by core team after field validation |
| `checks/community/accepted/` | accepted | yes (community mode) | Passed maintainer review + CI gates |
| `checks/community/proposed/` | proposed | only with `--include-proposed` | Submitted, awaiting review |

The legacy `checks/` root is treated as core for backward compatibility with
the original 112 checks. New checks should be authored in the appropriate
community location.

## Path from proposed to verified

1. Open a pull request that adds your check to `checks/community/proposed/`.
2. CI runs automated gates (described below). All gates must pass.
3. A maintainer reviews the check for correctness, false-positive rate, and
   metadata accuracy. Two maintainer approvals promote the check to
   `checks/community/accepted/`.
4. After at least six months of field data and a positive core-team vote,
   accepted checks may be promoted to `checks/community/verified/`.

## Authoring a check

Copy the template:

```bash
cp templates/check.sh checks/community/proposed/<NUMBER>-<short-name>.sh
```

Open the file. The first block is YAML metadata wrapped in a heredoc that
documents what the check is, who wrote it, and how it integrates with the
compliance frameworks. Fill in every required field. The second block is the
actual scan logic, which calls the `record` function exposed by the runner.

Your check must:

- Only read files. Never write outside `/tmp` or make network calls.
- Not call `eval`, `exec`, `source` of arbitrary input, or shell out to
  binaries that are not on the allowed list (`grep`, `find`, `awk`, `sed`,
  `cat`, `cut`, `sort`, `uniq`, `wc`, `head`, `tail`, `tr`, `xargs`).
- Complete in under 30 seconds against a typical fintech repo.
- Produce zero false positives against the known-good fixture corpus.
- Produce expected matches against the known-bad fixture corpus.

## Surfacing actionable findings

The `record` function accepts an optional 4th argument with multi-line
`file:line:content` findings. When present, those findings appear under
the corresponding FAIL/WARN row in the markdown report and on the
terminal in `--verbose` mode (or always on FAIL). This is what makes
findings actionable — auditors and developers can navigate from the
report directly to the offending source line.

Pattern your check like this:

```bash
hits=$(grep -rn --include="*.java" -E 'pattern' "$SRC" 2>/dev/null \
  | grep -vE '/test/|node_modules' || true)

if [[ -n "$hits" ]]; then
  count=$(echo "$hits" | wc -l | tr -d ' ')
  sample=$(echo "$hits" | head -10)
  record "FAIL" "P-XXX Short name" "$count occurrence(s) detected" "$sample"
else
  record "PASS" "P-XXX Short name" "No issues found"
fi
```

Cap findings to ~10 lines via `head` so the report stays scannable.
The runner truncates appropriately on terminal output as well.

## Required metadata

Every check must include a YAML metadata block at the top, wrapped in
`PRESTON_META` heredoc markers. Required fields:

- `schema_version: 1`
- `id` (e.g., `P-201` for community-proposed; range `200-999` reserved for
  community contributions to avoid collision with core)
- `name` (short title, under 60 characters)
- `description` (one paragraph)
- `category` (one of: `code-scan`, `compliance-evidence`, `live-monitoring`,
  `infra-scan`)
- `severity` (one of: `critical`, `high`, `medium`, `low`, `info`)
- `languages` (`any` or comma-separated list)
- `min_tier` (`free`, `pro`, or `enterprise`)
- `runtime_class` (`static-grep` for community contributions; other classes
  reserved for core)
- `evidence_required` (`true` or `false`)
- `version` (semver, start at `1.0.0`)
- `added_in` (the Preston-Check version this check first ships in)
- `author_name` (your name)
- `author_github` (your GitHub handle for attribution in reports)

Optional but strongly recommended:

- `frameworks` (comma-separated `Framework:Version:Control` strings)
- `cwe` (comma-separated CWE numbers)
- `owasp` (comma-separated OWASP references like `API2:2023`)
- `nist_csf` (comma-separated NIST CSF subcategories)
- `false_positive_rate` (`low`, `medium`, or `high`)
- `performance_class` (`fast` < 1s, `medium` < 10s, `slow` < 60s)
- `origin` (one-line narrative of where the pattern came from)

See `templates/check.sh` for a fully-filled example.

## Automated gates

Every PR runs through these gates in CI. A failure in any one blocks merge.

1. `shellcheck` on the script.
2. `tools/lint-check.sh` enforces the network-call/eval/file-write/binary
   policy and validates metadata against the schema.
3. Golden-fixture tests run the check against `tests/fixtures/good/` (must
   not match) and `tests/fixtures/bad/` (must match). Contributors include
   their own fixtures in the same PR.
4. The check must run against `tests/fixtures/typical-fintech/` in under
   30 seconds.
5. DCO sign-off (`git commit -s`) is required on every commit.

## Contributor License Agreement

First-time contributors must accept the Contributor License Agreement (see
`CLA.md`). The CLA grants the project the right to relicense your
contribution under the project license and into the commercial audit-package
layer. You retain copyright on your contributions.

## Attribution in reports

Every check fires with author attribution in the report. When `P-217` runs
and finds an issue, the report shows "P-217 (contributed by @yourhandle)
found 3 issues". This is intentional. Authors deserve credit, and visible
attribution incentivizes high-quality contributions.

## Bounty program

Once Preston-Check has paying customers, the project plans to pay $100–250
per accepted check, and additional bounties for contributors who reach
verified tier. Details will be published when the program launches. The
bounty does not change the contribution process, only adds a reward.

## Code of conduct

Be respectful in PR discussions. Maintainers reserve the right to close
PRs that violate the code of conduct or that appear designed in bad faith
(e.g., checks that try to evade the lint, contain backdoors, or claim
framework coverage they do not provide).

## Questions

Open a GitHub Discussion in the project repository. Maintainers and
community members can help with both check design and process questions.
