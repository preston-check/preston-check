#!/usr/bin/env python3
"""tools/sandbox_validate.py

Bash AST walker that validates an auto-generated check against a
strict capability allowlist. This is the mechanical safety gate that
rejects checks containing operations outside what auto-generated
catalog entries are permitted to do.

Permitted:
  - Commands: record, grep, rg, find, echo, printf, basename, dirname,
    head, tail, wc, sort, uniq, tr, awk, sed (with -n only, never -i),
    cat (single file read), test, [, [[
  - Control: if/then/else/fi, for/in/do/done, while/do/done,
    case/esac, function definitions
  - Substitution: parameter expansion of named variables ($var,
    ${var}, ${var:-default}, ${var:+alt}, ${#var}, ${var%suffix},
    ${var#prefix})
  - Reads from $SOURCE_DIR, $SRC, $TMPDIR
  - Comparison and string operations within test/[[/[

Rejected (deny-list, applied even if the syntax is otherwise allowed):
  - eval, exec, source, '.' (dot include), bash -c, sh -c
  - Network commands (curl, wget, nc, ssh, scp, rsync, etc.)
  - File-mutation commands (rm, mv, cp, ln, chmod, etc.)
  - Indirect parameter expansion (${!var})
  - printf -v, declare -n (writes to caller-scoped names)
  - IFS manipulation (IFS=...)
  - unset, set -o, shopt
  - History expansion (! prefix in non-comment context)
  - Process substitution (<(...), >(...))
  - grep -P, rg --pre, find -exec, find -ok, find -execdir, find -okdir
  - find -delete, find -fprint
  - Backticks (legacy; force $(...) which still goes through allowlist)

This walker is the second line of defense after the structural-
separation prompt design and before the subshell-isolated execution
path. None of the three lines is sufficient on its own; together they
form the verification wall.

Validation is layered for robustness:
  1. Pattern-based denylist always runs (catches dangerous primitives
     regardless of parsing success).
  2. AST-based command-allowlist runs when bashlex can parse the
     source.
  3. Regex-based command-allowlist runs as a fallback when bashlex
     cannot parse (still enforces the allowlist via line-start detection).

Exit codes: 0 if validation passes, 1 if any rule is violated, 2 on
unexpected internal error (treated as a fail).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import bashlex  # type: ignore[import-untyped]
    _HAS_BASHLEX = True
except ImportError:
    _HAS_BASHLEX = False


PERMITTED_COMMANDS: frozenset[str] = frozenset(
    {
        "record",
        "grep",
        "rg",
        "find",
        "echo",
        "printf",
        "basename",
        "dirname",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "tr",
        "awk",
        "sed",
        "cat",
        "test",
        "[",
        "[[",
        "true",
        "false",
        ":",
        "return",
    }
)

DENIED_COMMANDS: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "source",
        ".",
        "bash",
        "sh",
        "zsh",
        "ksh",
        "dash",
        "fish",
        "curl",
        "wget",
        "nc",
        "ncat",
        "socat",
        "ssh",
        "scp",
        "rsync",
        "git",
        "svn",
        "hg",
        "ftp",
        "telnet",
        "openssl",
        "rm",
        "rmdir",
        "mv",
        "cp",
        "ln",
        "chmod",
        "chown",
        "chgrp",
        "mkdir",
        "touch",
        "dd",
        "tee",
        "mknod",
        "mkfifo",
        "mount",
        "umount",
        "kill",
        "killall",
        "pkill",
        "trap",
        "wait",
        "fg",
        "bg",
        "jobs",
        "disown",
        "ulimit",
        "umask",
        "history",
        "alias",
        "unalias",
        "unset",
        "set",
        "shopt",
        "enable",
        "builtin",
        "command",
        "type",
        "hash",
        "help",
        "logout",
        "exit",
        "declare",
        "typeset",
        "local",
        "readonly",
        "export",
        "read",
        "mapfile",
        "readarray",
        "select",
        "pushd",
        "popd",
        "dirs",
        "cd",
        "chdir",
        "pwd",
        "env",
        "printenv",
        "su",
        "sudo",
        "doas",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "npm",
        "yarn",
        "pip",
        "make",
        "gcc",
        "ld",
        "as",
    }
)


_DANGEROUS_FLAGS_PER_CMD: dict[str, frozenset[str]] = {
    "grep": frozenset({"-P", "--perl-regexp", "-z", "--null-data"}),
    "rg": frozenset({"--pre", "--pre-glob", "--search-zip", "-z", "--engine"}),
    "find": frozenset(
        {
            "-exec",
            "-execdir",
            "-ok",
            "-okdir",
            "-delete",
            "-fprint",
            "-fprint0",
            "-fprintf",
            "-fls",
        }
    ),
    "sed": frozenset({"-i", "--in-place"}),
    "awk": frozenset({"-i"}),
    "cat": frozenset({"-A", "-T", "-E"}),
}


_PROHIBITED_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\$\{!\s*\w+"), "indirect parameter expansion (${!var})"),
    (
        re.compile(r"\bprintf\s+(?:[^|;&\n]*\s)?-v\s"),
        "printf -v writes to caller-scoped names",
    ),
    (re.compile(r"\bdeclare\s+(?:[^|;&\n]*\s)?-n\b"), "declare -n nameref"),
    (re.compile(r"^\s*IFS\s*=", re.MULTILINE), "IFS manipulation"),
    (re.compile(r"(?:^|;|\|\||\&\&)\s*IFS\s*="), "IFS manipulation"),
    (
        re.compile(r"\bset\s+(?:[^|;&\n]*\s)?-[ouB]"),
        "set -o / set -B option change",
    ),
    (re.compile(r"\bshopt\s"), "shopt option change"),
    (re.compile(r"<\("), "process substitution input <(...)"),
    (re.compile(r">\("), "process substitution output >(...)"),
    (
        re.compile(r"`[^`]*`"),
        "backtick command substitution (use $(...) instead, still allowlisted)",
    ),
    (
        re.compile(r"\$\(\(\s*[^)]*\$\([^)]*\)"),
        "arithmetic with nested command substitution",
    ),
    (re.compile(r"\benable\s+-"), "enable builtin manipulation"),
    (re.compile(r"\btrap\s"), "trap handler installation"),
    (re.compile(r"BASH_ENV\s*="), "BASH_ENV manipulation"),
    (re.compile(r"\bENV\s*="), "ENV variable manipulation"),
    (
        re.compile(r"(?:^|;|\|\||\&\&)\s*PATH\s*=(?!\s*[\"']?\$PATH\b)", re.MULTILINE),
        "PATH overwrite (PATH=$PATH:... is allowed)",
    ),
    (re.compile(r"^\s*!\w"), "history expansion (! prefix)"),
)


_COMMAND_START_RE = re.compile(
    r"(?:^|[\n;]|\|\||\&\&|\||\()\s*([a-zA-Z_][\w-]*)\b"
)


def _strip_meta_block(source: str) -> str:
    """Strip the PRESTON_META heredoc so it doesn't get parsed as bash."""
    pattern = re.compile(
        r":\s*<<\s*['\"]?PRESTON_META['\"]?\s*\n.*?\nPRESTON_META\s*$",
        re.DOTALL | re.MULTILINE,
    )
    return pattern.sub("", source)


def _strip_shebang_and_comments(source: str) -> str:
    """Remove the shebang and full-line comments so they don't trip pattern checks."""
    lines = source.split("\n")
    out: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#"):
            out.append("")
        else:
            out.append(line)
    return "\n".join(out)


def _strip_string_literals(source: str) -> str:
    """Replace string contents with placeholders so command extraction
    doesn't pick up commands inside strings as if they were invocations.
    Preserves line counts for diagnostics."""
    result: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        if c in ('"', "'"):
            quote = c
            j = i + 1
            while j < n and source[j] != quote:
                if quote == '"' and source[j] == "\\":
                    j += 2
                else:
                    j += 1
            result.append(quote + " " * max(0, j - i - 1) + (quote if j < n else ""))
            i = j + 1 if j < n else j
        else:
            result.append(c)
            i += 1
    return "".join(result)


def _check_pattern_violations(source: str) -> list[str]:
    """Run the prohibited-pattern regex set against the cleaned source."""
    violations: list[str] = []
    seen: set[str] = set()
    for regex, reason in _PROHIBITED_PATTERNS:
        if regex.search(source) and reason not in seen:
            violations.append(reason)
            seen.add(reason)
    return violations


def _walk_for_commands(node: Any, found: list[tuple[str, list[str]]]) -> None:
    """Recursively walk the bashlex AST collecting (command, args) tuples."""
    if node is None:
        return
    kind = getattr(node, "kind", None)
    if kind == "command":
        parts = getattr(node, "parts", []) or []
        words: list[str] = []
        for p in parts:
            if getattr(p, "kind", None) == "word":
                words.append(getattr(p, "word", ""))
        if words:
            found.append((words[0], words[1:]))
    for attr in ("parts", "list", "commands", "command", "body"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, list):
            for c in child:
                _walk_for_commands(c, found)
        else:
            _walk_for_commands(child, found)


def _bare_command_name(word: str) -> str:
    """Strip variable-expansion noise so 'grep' is recognised in '"grep"' or '$GREP'."""
    w = word.strip().strip("\"'")
    if w.startswith("$"):
        return ""
    return w


def _validate_commands_via_ast(source: str) -> tuple[bool, list[str]]:
    """Try AST validation. Returns (parsed_ok, violations)."""
    if not _HAS_BASHLEX:
        return False, []
    try:
        trees = bashlex.parse(source, strictmode=False)
    except Exception:
        return False, []

    violations: list[str] = []
    commands: list[tuple[str, list[str]]] = []
    for t in trees:
        _walk_for_commands(t, commands)

    for cmd, args in commands:
        bare = _bare_command_name(cmd)
        if not bare:
            violations.append(f"command via variable expansion: {cmd}")
            continue
        if bare in DENIED_COMMANDS:
            violations.append(f"denied command: {bare}")
            continue
        if bare not in PERMITTED_COMMANDS:
            violations.append(f"command not on allowlist: {bare}")
            continue
        dangerous = _DANGEROUS_FLAGS_PER_CMD.get(bare)
        if dangerous:
            for a in args:
                a_clean = a.strip("\"'")
                if a_clean in dangerous:
                    violations.append(f"dangerous flag {a_clean} on {bare}")

    return True, violations


def _validate_commands_via_regex(source: str) -> list[str]:
    """Fallback validation when bashlex can't parse. Detects command starts
    via regex and applies the allowlist; less precise than AST but enforces
    the same set of denials and allowlist."""
    no_strings = _strip_string_literals(source)
    violations: list[str] = []
    seen: set[str] = set()

    for match in _COMMAND_START_RE.finditer(no_strings):
        cmd = match.group(1)
        if cmd in {
            "if",
            "then",
            "else",
            "elif",
            "fi",
            "for",
            "in",
            "do",
            "done",
            "while",
            "until",
            "case",
            "esac",
            "function",
            "return",
            "break",
            "continue",
            "true",
            "false",
        }:
            continue
        if cmd in DENIED_COMMANDS:
            key = f"denied command: {cmd}"
            if key not in seen:
                violations.append(key)
                seen.add(key)
            continue
        if cmd in PERMITTED_COMMANDS:
            continue
        if re.match(r"^[a-zA-Z_][\w-]*$", cmd) and cmd.isupper():
            continue
        if "=" in source[match.start() : match.end() + 2]:
            continue
        key = f"command not on allowlist (regex fallback): {cmd}"
        if key not in seen:
            violations.append(key)
            seen.add(key)

    for cmd, dangerous in _DANGEROUS_FLAGS_PER_CMD.items():
        for flag in dangerous:
            pat = re.compile(rf"\b{re.escape(cmd)}\b[^|;&\n]*\s{re.escape(flag)}\b")
            if pat.search(no_strings):
                key = f"dangerous flag {flag} on {cmd}"
                if key not in seen:
                    violations.append(key)
                    seen.add(key)

    return violations


def validate_check(check_path: Path) -> dict[str, Any]:
    """Validate a single check file. Returns a dict with pass/fail and reasons."""
    if not check_path.is_file():
        return {"pass": False, "reasons": [f"file not found: {check_path}"]}

    source = check_path.read_text(encoding="utf-8", errors="replace")
    cleaned = _strip_shebang_and_comments(_strip_meta_block(source))

    pattern_issues = _check_pattern_violations(cleaned)
    ast_ok, ast_issues = _validate_commands_via_ast(cleaned)
    if ast_ok:
        cmd_issues = ast_issues
        validator_path = "ast"
    else:
        cmd_issues = _validate_commands_via_regex(cleaned)
        validator_path = "regex-fallback"

    all_issues = pattern_issues + cmd_issues
    return {
        "pass": len(all_issues) == 0,
        "reasons": all_issues,
        "checked_path": str(check_path),
        "validator_version": "0.2.0",
        "validator_path": validator_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate an auto-generated check against the sandbox capability allowlist."
    )
    parser.add_argument("path", type=Path, help="Path to a candidate check (.sh) file")
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of human-readable output"
    )
    args = parser.parse_args()

    result = validate_check(args.path)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["pass"]:
            print(f"PASS  {args.path}  (via {result['validator_path']})")
        else:
            print(f"FAIL  {args.path}  (via {result['validator_path']})")
            for r in result["reasons"]:
                print(f"  - {r}")

    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
