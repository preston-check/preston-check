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

Validation is layered:
  1. Pattern-based denylist always runs (catches dangerous primitives
     regardless of parsing success).
  2. [[ ... ]] conditionals are normalised to a parseable no-op so
     bashlex can parse real checks via its sound AST path (bashlex does
     not implement [[ ]] and would otherwise reject every check).
  3. AST-based command-allowlist runs on the normalised source. When
     bashlex is present but still cannot parse (case/esac, coproc, line
     continuations, ...), the check is REJECTED (fail closed) — an
     unparseable check must never ship. The weaker regex scan is used
     only when bashlex is not installed at all (never in CI).

Historical note: awk/sed/cat/cut were removed from the allowlist after a
review found program-text bypasses (awk print|"cmd", awk print>file, sed
e/w/r) that the AST walker cannot see, plus unrestricted arbitrary-file
reads. Zero shipped auto-checks used them; grep/rg/find cover detection.

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
        "test",
        "[",
        "[[",
        "true",
        "false",
        ":",
        "return",
        "break",
        "continue",
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
        # awk/sed/cat/cut removed from the allowlist entirely: zero shipped
        # auto-checks use them, and each carries a program-text bypass the
        # AST walker cannot see (awk system()/print|"cmd"/print>file, sed
        # e/w/r commands) or an unrestricted arbitrary-file read (cat/cut).
        # grep/rg/find fully cover static detection. Denied explicitly so the
        # rejection reason is clear.
        "awk",
        "sed",
        "cat",
        "cut",
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
    "awk": frozenset({"-i", "-f", "--file"}),
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
    # awk program-text shell escapes — the AST walker only sees "awk" as a command
    # word; it never inspects the program-text argument where system() and pipe-getline
    # can invoke arbitrary subcommands using only allowlisted words.
    (
        re.compile(r"\bawk\b[^|;&\n]*'[^']*\bsystem\s*\("),
        "awk program-text shell escape via system()",
    ),
    (
        re.compile(r'\bawk\b[^|;&\n]*"[^"]*\bsystem\s*\('),
        "awk program-text shell escape via system()",
    ),
    (
        re.compile(r"\bawk\b[^|;&\n]*'[^']*?\|\s*getline\b"),
        "awk program-text pipe getline (command injection)",
    ),
    (
        re.compile(r'\bawk\b[^|;&\n]*"[^"]*?\|\s*getline\b'),
        "awk program-text pipe getline (command injection)",
    ),
    # awk output-pipe: print ... | "command" spawns a shell. Distinct from
    # getline; this is the most common awk shell-escape.
    (
        re.compile(r"\bawk\b[^\n]*(?:print|printf)[^\n]*\|\s*\""),
        "awk program-text output pipe to command (print | \"cmd\")",
    ),
    # awk output redirection: print ... > "file" / >> "file" writes files.
    # Runs against non-stripped source so the awk program interior is visible.
    (
        re.compile(r"\bawk\b[^\n]*(?:print|printf)[^\n]*>>?\s*[\"'/]"),
        "awk program-text output redirection to file",
    ),
    # GNU sed 'e' command (standalone, not the s///e flag) executes the
    # pattern space or a given command as a shell command.
    (
        re.compile(r"\bsed\b[^\n]*'[^']*(?:^|;|\n)\s*[0-9$/]*\s*e\b"),
        "sed 'e' command executes shell (GNU sed)",
    ),
    (
        re.compile(r"\bsed\b[^\n]*(?:-e\s+)?['\"][0-9]*e\s"),
        "sed 'e' command executes shell (GNU sed)",
    ),
    # sed w/W/r/R read or write arbitrary files, defeating read-only.
    (
        re.compile(r"\bsed\b[^\n]*['\"][^'\"]*[0-9$/,]*\s*[wWrR]\s+\S"),
        "sed w/W/r/R file read/write is not permitted",
    ),
    # awk program loaded from a variable reference — inline literal programs can be
    # statically inspected; variable-assembled programs cannot.
    # Matches awk "$VAR", awk $VAR, awk "${VAR}" when the variable is the FIRST argument
    # (i.e., the program-text position). File arguments like "$SRC" appear later in the
    # command and are not preceded immediately by `awk\s+`.
    (
        re.compile(r"\bawk\s+\"?\$\{?\w"),
        "awk program from variable reference (cannot inspect program text; use inline literal)",
    ),
    # sed s///e flag executes the replacement string as a shell command.
    # The -i flag is blocked via _DANGEROUS_FLAGS_PER_CMD; this blocks the e flag
    # which lives inside the substitution command string, not as a CLI argument.
    (
        re.compile(r"\bsed\b[^|;&\n]*'[^']*s/[^/]*/[^/]*/[a-z]*e"),
        "sed s///e flag executes replacement text as shell command",
    ),
    (
        re.compile(r'\bsed\b[^|;&\n]*"[^"]*s/[^/]*/[^/]*/[a-z]*e'),
        "sed s///e flag executes replacement text as shell command",
    ),
    # ANSI-C quoting ($'...') can encode arbitrary bytes including banned command names
    # (e.g. $'\x65\x76\x61\x6c' decodes to "eval"). It is not needed in any legitimate
    # auto-generated check, so it is prohibited unconditionally.
    (
        # Anchored to a token-start position so the ubiquitous blank-line
        # idiom grep -v '^$' (where $' is the anchor '$' plus a closing
        # quote, not an ANSI-C quote opener) is not falsely flagged.
        re.compile(r"(?:^|[\s=(:,\"])\$'"),
        "ANSI-C quoting ($'...') is not permitted in auto-generated checks",
    ),
    # Backslash-newline line continuation allows a single logical command to span
    # multiple physical lines. Single-line regex patterns (including the awk-herestring
    # prohibition) stop at \n, so a continuation can split a banned construct across
    # lines to evade pattern matching. Legitimate auto-generated checks don't need
    # line continuations — prohibit them unconditionally.
    (
        re.compile(r"\\\s*\n"),
        "backslash-newline line continuation is not permitted in auto-generated checks",
    ),
    # Brace command groups ({ cmd; }) are not used in legitimate static-grep checks
    # and create a command-start position that the regex fallback's COMMAND_START_RE
    # does not recognise, allowing denied commands placed inside { } to slip through
    # when bashlex fails to parse the source.
    (
        re.compile(r"(?:^|;|\|\||\&\&|\n)\s*\{"),
        "brace command group ({ }) is not permitted in auto-generated checks",
    ),
    # awk program via here-string — <<<'program' is a redirect node that neither
    # the AST walker nor the inline-program-text patterns inspect. The content of
    # the here-string cannot be statically analysed, so any awk-with-herestring
    # invocation is blocked unconditionally.
    (
        re.compile(r"\bawk\b[^|;&\n]*<<<"),
        "awk program via here-string (cannot inspect program text)",
    ),
    # Output redirection to a real file — allow only /dev/null and fd-redirects (&1/&2).
    # Checks must be read-only: printf/echo/cat writing to arbitrary paths is disallowed.
    # This pattern runs against string-literal-stripped source (see _check_pattern_violations)
    # to avoid false positives from grep patterns that contain > inside quoted arguments.
    (
        re.compile(r">+(?!\s*(?:/dev/null\b|&(?:1|2)(?:\b|>)))\s*\S"),
        "output redirection to file (only /dev/null and &2 are permitted)",
    ),
)


# Command-start positions for the no-bashlex fallback. Includes ')' (case
# branches, subshell close) and '&' (background) in addition to line starts,
# ';', pipes, '&&'/'||', and '('. Command-introducing keywords (then/do/else/
# elif) and case terminators (;;) are normalised to ';' before scanning so a
# denied command in those positions (e.g. 'y) curl' or 'then curl') is still
# detected. '{'/'}' are deliberately excluded to avoid matching ${var}.
_COMMAND_START_RE = re.compile(
    r"(?:^|[\n;)&]|\|\||\&\&|\||\()\s*([a-zA-Z_][\w-]*)\b"
)

_KEYWORD_TO_SEP_RE = re.compile(r"\b(?:then|do|else|elif)\b|;;&?|;&")


def _extract_command_subs(source: str) -> tuple[str, list[str]]:
    """Pull out every $(...) command substitution, replacing each with a
    neutral placeholder and returning the interiors for independent validation.

    bashlex cannot parse ||/&& inside $(...) (a legitimate construct like
    $(rg -c X "$SRC" | wc -l || echo 0)), and it blanks nothing — so validating
    substitution interiors separately both works around that limitation and
    removes a blind spot (command subs inside double quotes). Single-quoted
    regions are copied verbatim (no expansion there). $((...)) arithmetic is
    left in place (it cannot invoke commands; nested $() inside it is caught by
    the always-on denylist). Extraction runs before [[ ]] normalisation so a
    substitution embedded in a test is preserved intact, not mangled.
    """
    inners: list[str] = []
    out: list[str] = []
    i, n = 0, len(source)
    state = "normal"  # normal | single | double
    while i < n:
        c = source[i]
        if state == "single":
            out.append(c)
            if c == "'":
                state = "normal"
            i += 1
            continue
        if state == "double":
            if c == "\\" and i + 1 < n:
                out.append(source[i : i + 2])
                i += 2
                continue
            if c == '"':
                state = "normal"
                out.append(c)
                i += 1
                continue
            # fall through to $( detection inside double quotes
        else:  # normal
            if c == "'":
                state = "single"
                out.append(c)
                i += 1
                continue
            if c == '"':
                state = "double"
                out.append(c)
                i += 1
                continue
        # $( command substitution (but not $(( arithmetic ))
        if c == "$" and i + 1 < n and source[i + 1] == "(" and not (
            i + 2 < n and source[i + 2] == "("
        ):
            depth = 1
            j = i + 2
            iq: str | None = None
            while j < n and depth > 0:
                cj = source[j]
                if iq:
                    if cj == "\\" and iq == '"' and j + 1 < n:
                        j += 2
                        continue
                    if cj == iq:
                        iq = None
                elif cj in ('"', "'"):
                    iq = cj
                elif cj == "(":
                    depth += 1
                elif cj == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if depth == 0:
                inners.append(source[i + 2 : j])
                out.append("PSUBST")
                i = j + 1
                continue
            # unbalanced — leave verbatim; bashlex will fail → fail closed
        out.append(c)
        i += 1
    return "".join(out), inners


def _normalize_double_bracket(source: str) -> str:
    """Rewrite [[ ... ]] conditional expressions into a parseable no-op command
    so bashlex can parse the check via its sound AST path.

    bashlex does not implement [[ ]] and raises on the leading unary operators
    (-z, -n, ...) that every generated check uses, which would otherwise force
    the weaker regex fallback for 100% of real checks. We replace each
    [[ <expr> ]] with ': <expr-with-test-operators-neutralised>'. The ':' is the
    permitted no-op builtin; any $(...) command substitution embedded in the
    test is preserved as an argument so the AST walker still descends into it
    and enforces the allowlist there. Test-internal operators (&&, ||, !, ;)
    are blanked so the residue is a single simple command's argument list rather
    than several commands beginning with bare operands like '-n'.
    """
    def repl(m: re.Match[str]) -> str:
        inner = re.sub(r"&&|\|\||;|(?<![0-9<>])!", " ", m.group(1))
        return ": " + inner
    return re.sub(r"\[\[(.*?)\]\]", repl, source, flags=re.DOTALL)


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
            if j >= n:
                # Unterminated string literal — return the un-stripped remainder
                # (fail-safe). Swallowing the rest would blind the redirect
                # prohibition to any >/file patterns that follow the unclosed quote.
                return "".join(result) + source[i:]
            result.append(quote + " " * max(0, j - i - 1) + quote)
            i = j + 1
        else:
            result.append(c)
            i += 1
    return "".join(result)


def _check_pattern_violations(source: str) -> list[str]:
    """Run the prohibited-pattern regex set against the cleaned source.

    The redirect pattern runs against string-literal-stripped source to avoid
    false positives from grep/awk patterns that contain > inside quoted arguments
    (e.g. grep -rn "size > 0" "$SRC"). All other patterns run against the full
    cleaned source so that inline awk/sed program-text strings are still visible.
    """
    violations: list[str] = []
    seen: set[str] = set()
    no_strings = _strip_string_literals(source)
    for regex, reason in _PROHIBITED_PATTERNS:
        src = no_strings if "redirection" in reason else source
        if regex.search(src) and reason not in seen:
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
    """Try AST validation on already-normalised source. Returns (parsed_ok,
    violations)."""
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
    # Normalise command-introducing keywords and case terminators to ';' so the
    # scanner recognises commands that follow them (then curl, y) curl, ;;).
    no_strings = _KEYWORD_TO_SEP_RE.sub(";", no_strings)
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

    # The always-on pattern denylist runs against the un-normalised source so
    # inline awk/sed program text and ANSI-C quoting are still visible.
    pattern_issues = _check_pattern_violations(cleaned)

    if _HAS_BASHLEX:
        # Validate the top-level source and every command-substitution interior
        # as independent command contexts. Extraction runs first so a $(...) is
        # never mangled by [[ ]] normalisation; each interior is then processed
        # the same way (it may itself contain [[ ]] or nested $()).
        cmd_issues = []
        validator_path = "ast"
        worklist = [cleaned]
        processed = 0
        while worklist and processed < 500:  # bound guards against pathological nesting
            processed += 1
            residue, inners = _extract_command_subs(worklist.pop())
            worklist.extend(inners)
            ast_ok, ast_issues = _validate_commands_via_ast(
                _normalize_double_bracket(residue)
            )
            if not ast_ok:
                # Fail closed. A fragment the validator cannot parse must never
                # ship; the old behaviour (fall through to a weaker regex scan)
                # let constructs bashlex rejects — case/esac, coproc, line
                # continuations — smuggle denied commands past the wall.
                cmd_issues = [
                    "unparseable by validator (auto-checks must use the standard grep skeleton)"
                ]
                validator_path = "ast-reject"
                break
            cmd_issues.extend(ast_issues)
    else:
        # bashlex unavailable (never in CI, which installs it). Degrade to the
        # hardened regex scan rather than fail every check in local dev.
        cmd_issues = _validate_commands_via_regex(_normalize_double_bracket(cleaned))
        validator_path = "regex-fallback"

    all_issues = pattern_issues + cmd_issues
    return {
        "pass": len(all_issues) == 0,
        "reasons": all_issues,
        "checked_path": str(check_path),
        "validator_version": "0.3.0",
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
