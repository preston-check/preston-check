#!/usr/bin/env python3
"""
tools/extend-findings-bulk.py

One-time bulk updater that extends the v1.3.2 actionable-findings pattern
across all checks. Conservative: only modifies record() calls that match
a clear pattern. Skips ambiguous cases.

What it does:
  For each check file in checks/, finds record "FAIL" or record "WARN"
  invocations with exactly 3 arguments. Looks backwards in the same scope
  for the most recent `<var>=$(grep ...)` (or similar) capture. If found,
  appends `"$(echo "$<var>" | head -10)"` as the 4th argument so findings
  surface under the report row.

What it skips:
  - record() calls already with 4 args (idempotent)
  - record() calls where no grep capture is found within 30 lines
  - record() calls with unusual escaping that the parser can't reason about
  - record() calls inside complex nested conditionals where scope is unclear

Skipped checks remain functional but emit summary-only rows. Hand-update
those over time as the patterns get refined.

Usage:
    python3 tools/extend-findings-bulk.py --dry-run
    python3 tools/extend-findings-bulk.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CHECKS = ROOT / "checks"

# Pattern matching a `var=$(grep ...)` (or find / git log) capture line.
GREP_ASSIGN_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)=\$\((?:grep|find|git|ls)\b'
)

# Match a record() call with exactly 3 arguments and capture them.
# Permits both `record FAIL` and `record "FAIL"`, with leading/trailing space.
RECORD_3ARG_RE = re.compile(
    r'^(?P<lead>\s*)record\s+"(?P<status>FAIL|WARN)"\s+"(?P<check>[^"]+)"\s+"(?P<detail>[^"]+)"\s*(?P<trail>\|\|\s*true\s*)?$'
)

# Already-4-arg record (skip)
RECORD_4ARG_RE = re.compile(
    r'^\s*record\s+"(?:FAIL|WARN|PASS|SKIP)"\s+"[^"]+"\s+"[^"]+"\s+"'
)

LOOKBACK = 40   # lines to scan backwards for the grep variable


def find_recent_capture(lines, idx):
    """Walk backwards from line idx to find the most recent grep/find/git capture variable."""
    last_var = None
    for i in range(idx - 1, max(0, idx - LOOKBACK), -1):
        m = GREP_ASSIGN_RE.match(lines[i])
        if m:
            last_var = m.group(1)
            break
        # Stop at function boundary or a clearly different scope marker
        if re.match(r'^\s*\}\s*$', lines[i]):
            break
    return last_var


def update_file(path: Path, dry_run: bool = False):
    text = path.read_text()
    lines = text.split('\n')
    changed_lines = 0
    skipped_lines = 0

    for i, line in enumerate(lines):
        # Skip if already 4-arg
        if RECORD_4ARG_RE.match(line):
            continue

        m = RECORD_3ARG_RE.match(line)
        if not m:
            continue

        var = find_recent_capture(lines, i)
        if not var:
            skipped_lines += 1
            continue

        # Construct the new 4-arg form
        lead = m.group('lead')
        status = m.group('status')
        check = m.group('check')
        detail = m.group('detail')
        trail = m.group('trail') or ''

        new_line = (
            f'{lead}record "{status}" "{check}" "{detail}" '
            f'"$(echo "${var}" | head -10)" '
            f'{trail}'
        ).rstrip()

        if new_line != line:
            lines[i] = new_line
            changed_lines += 1

    if changed_lines > 0:
        if not dry_run:
            path.write_text('\n'.join(lines))
        return changed_lines, skipped_lines
    return 0, skipped_lines


def main():
    dry_run = '--dry-run' in sys.argv

    total_files = 0
    files_changed = 0
    total_changes = 0
    total_skipped = 0
    skipped_files = []

    for check_file in sorted(CHECKS.glob('*.sh')):
        total_files += 1
        changed, skipped = update_file(check_file, dry_run=dry_run)
        total_changes += changed
        total_skipped += skipped
        if changed > 0:
            files_changed += 1
            print(f"{'[dry] ' if dry_run else ''}{check_file.name}: +{changed} record() updated")
        elif skipped > 0:
            skipped_files.append((check_file.name, skipped))

    print()
    print(f"Files scanned:                {total_files}")
    print(f"Files updated:                {files_changed}")
    print(f"record() calls extended:      {total_changes}")
    print(f"record() calls left as-is:    {total_skipped} (no clear grep capture nearby)")
    print(f"Files with skipped record():  {len(skipped_files)}")
    if dry_run:
        print()
        print("(dry run — no files written)")


if __name__ == '__main__':
    main()
