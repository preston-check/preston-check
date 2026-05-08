---
title: "Preston-Check — local git hooks"
audience: "maintainer (operator) + collaborators"
---

# Local git hooks

This directory contains opt-in local git hooks. They are committed to
the repository so any clone can use them, but they are not active by
default — each clone must opt in via a one-time configuration.

## Activate

```
git config --local core.hooksPath .githooks
```

This change is local to your clone (stored in `.git/config`, not
committed). It tells git to load hooks from `.githooks/` instead of
the default `.git/hooks/`.

To deactivate later: `git config --local --unset core.hooksPath`.

## Hooks

### `pre-commit`

Pause-and-confirm gate for changes touching `.github/workflows/**`.

This is the local substitute for GitHub-side rulesets-based
workflow-file path protection (see Phase 9 in the activation plan;
rulesets path-restrict was unavailable on this repo's GitHub edition).

Behaviour:

- Commits that don't touch workflow files: hook exits silently, commit
  proceeds normally.
- Commits that touch workflow files: hook prints the list of affected
  files and prompts for explicit `yes` confirmation. Anything other
  than `yes` aborts the commit.
- Bypass for legitimate rapid iteration: set
  `PRESTON_ALLOW_WORKFLOW_EDITS=1` in the environment before running
  `git commit`. The variable is not persisted across shells, so the
  protection re-activates on the next session.

### Why this hook exists

The auto-evolving threat-intel pipeline orchestrates merge gates via
GitHub Actions workflows. A careless edit to those workflows could
weaken the verification wall (sandbox, validation, adversarial loop)
without triggering any other safety net. The hook adds a "pause and
think" gate when workflow files are about to be committed.

For a multi-collaborator setup, a stronger control is GitHub-side
ruleset path protection; install that and the hook becomes
redundant (but not harmful — defense in depth). See
`docs/threat-intel-pipeline-design.md` for the broader threat model.
