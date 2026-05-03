#!/usr/bin/env python3
"""
tools/fixup-bulk-findings.py

Cleanup pass after extend-findings-bulk.py. The bulk updater sometimes
picked count variables (assigned via `wc -l` or `grep -c`) instead of
file-list variables. This script identifies those cases and strips the
4th argument from record() calls where the captured variable is a count.

Strategy:
  1. Find lines like:  record "..." "..." "..." "$(echo "$X" | head -10)"
  2. Look back for X's definition.
  3. If X = $(... | wc -l ...) or $(grep -c ...) or $(... | head -N | wc -l)
     it's a count, not findings → remove the 4th arg.
  4. Otherwise leave the line alone.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CHECKS = ROOT / "checks"

# Pattern: record line with our injected 4th arg referencing $X
RECORD_WITH_FINDINGS_RE = re.compile(
    r'^(?P<head>\s*record\s+"(?:FAIL|WARN)"\s+"[^"]+"\s+"[^"]+")\s+"\$\(echo\s+"\$([A-Za-z_][A-Za-z0-9_]*)"\s*\|\s*head\s+-10\)"\s*(?P<trail>\|\|\s*true\s*)?$'
)

# Variable assignment patterns that produce a COUNT (not findings)
COUNT_ASSIGN_PATTERNS = [
    re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*=\$\(.*\|\s*wc\s+-l'),
    re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*=\$\(grep\s+-c'),
    re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*=\$\(echo\s+"\$[^"]*"\s*\|\s*wc'),
    re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*=\$\(\[\[\s+-n.*wc\s+-l'),
]

LOOKBACK = 60


def is_count_var(lines, target_idx, var_name):
    """Walk backwards from target_idx to find the assignment of var_name and check if it's a count."""
    var_re = re.compile(rf'^\s*{re.escape(var_name)}=')
    for i in range(target_idx - 1, max(0, target_idx - LOOKBACK), -1):
        line = lines[i]
        if var_re.match(line):
            for pattern in COUNT_ASSIGN_PATTERNS:
                if pattern.match(line):
                    return True
            return False
    return False


def fix_file(path: Path, dry_run: bool = False):
    text = path.read_text()
    lines = text.split('\n')
    fixed = 0

    for i, line in enumerate(lines):
        m = RECORD_WITH_FINDINGS_RE.match(line)
        if not m:
            continue
        var_name = m.group(2)
        if is_count_var(lines, i, var_name):
            new_line = m.group('head')
            trail = m.group('trail') or ''
            if trail:
                new_line += ' ' + trail
            lines[i] = new_line
            fixed += 1

    if fixed > 0 and not dry_run:
        path.write_text('\n'.join(lines))
    return fixed


def main():
    dry_run = '--dry-run' in sys.argv
    total = 0
    files = 0
    for f in sorted(CHECKS.glob('*.sh')):
        n = fix_file(f, dry_run=dry_run)
        if n > 0:
            files += 1
            total += n
            print(f"{'[dry] ' if dry_run else ''}{f.name}: {n} count-var finding(s) stripped")
    print()
    print(f"Files fixed: {files}")
    print(f"record() calls cleaned: {total}")
    if dry_run:
        print("(dry run)")


if __name__ == '__main__':
    main()
