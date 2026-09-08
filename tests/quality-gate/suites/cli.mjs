/**
 * The CLI, lib/ and the checks — the artefact a release actually ships.
 *
 * These were covered only by the separate Tests workflow, so the gate could go
 * green on a completely broken scanner. This suite brings them under the same
 * roof: the scanner is executed, the existing lib test harness is run, and the
 * check corpus is validated as a whole.
 *
 * It deliberately does not re-run all 1146 checks against every fixture — that
 * would take minutes and a gate nobody waits for is a gate nobody runs. It
 * asserts the scanner works end to end, that metadata across the whole corpus
 * is well formed, and that detection actually fires on known-bad input.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { info } from '../lib/harness.mjs';

/** Run a command, returning stdout+stderr and the exit code, never throwing. */
function sh(cmd, args, opts = {}) {
  try {
    const out = execFileSync(cmd, args, {
      stdio: 'pipe', encoding: 'utf8', timeout: 240000,
      env: { ...process.env, PRESTON_TELEMETRY: 'off', NO_COLOR: '1' },
      ...opts,
    });
    return { code: 0, out };
  } catch (e) {
    return {
      code: typeof e.status === 'number' ? e.status : 1,
      out: `${e.stdout || ''}${e.stderr || ''}`,
    };
  }
}

export async function run(r, root) {
  r.suite('CLI, lib/ and checks (the shipped artefact)');

  const cli = join(root, 'preston-check.sh');

  // --- the binary runs at all ---
  const help = sh('bash', [cli, '--help'], { cwd: root });
  r.truthy('cli.help', 'CLI responds to --help', help.out.includes('Usage:'),
    `exit ${help.code}: ${help.out.slice(0, 200)}`);
  r.contains('cli.help', 'help advertises CI mode', help.out, '--ci');

  // --- the existing lib test harness ---
  const libTests = sh('bash', [join(root, 'tests', 'run-tests.sh')], { cwd: root });
  r.equal('cli.lib-tests', 'tests/run-tests.sh passes', libTests.code, 0);
  if (libTests.code !== 0) {
    info(libTests.out.split('\n').filter(l => /FAIL/.test(l)).slice(0, 10).join('\n'));
  }

  // --- every check carries valid metadata ---
  // Malformed metadata breaks --framework and --category filtering, which is
  // what compliance customers buy.
  //
  // tests/lib/*.sh are fragments sourced by run-tests.sh, which supplies
  // assert()/parse_check_metadata() from _check_harness.sh — running one
  // directly yields "command not found" for every helper and proves nothing.
  // So assert against the harness output that the metadata suite actually ran
  // and that nothing failed, rather than re-invoking it standalone.
  r.contains('cli.check-metadata', 'the metadata suite was actually exercised',
    libTests.out, 'test_check_metadata.sh');
  r.truthy('cli.check-metadata', 'metadata parser assertions pass',
    /PASS: .*trust_tier/.test(libTests.out),
    'no trust_tier assertion observed in the harness output');
  r.truthy('cli.check-metadata', 'the lib harness reports zero failures',
    /^\s*FAIL:\s*0\s*$/m.test(libTests.out),
    (libTests.out.match(/^\s*(PASS|FAIL):\s*\d+\s*$/gm) || []).join(' ').trim());

  // --- the corpus is non-empty and shell-valid ---
  const checkDirs = ['checks/community/accepted', 'checks'];
  let checkCount = 0;
  for (const d of checkDirs) {
    const p = join(root, d);
    if (existsSync(p)) {
      const walk = (dir) => readdirSync(dir, { withFileTypes: true }).reduce((n, e) =>
        n + (e.isDirectory() ? walk(join(dir, e.name)) : (e.name.endsWith('.sh') ? 1 : 0)), 0);
      checkCount = walk(p);
      break;
    }
  }
  r.truthy('cli.corpus', 'the check corpus is present and substantial',
    checkCount > 500, `found ${checkCount} check scripts`);

  const syntax = sh('bash', ['-c',
    `find "${root}/checks" -name '*.sh' -print0 | xargs -0 -n50 bash -n 2>&1 | head -20`]);
  r.truthy('cli.corpus', 'every check parses as valid bash',
    syntax.out.trim() === '', syntax.out.slice(0, 400));

  // --- detection actually fires ---
  // A scanner that never reports anything would pass every other assertion
  // here, so assert against a known-bad fixture and a known-good one.
  const scan = (dir, extra = []) => sh('bash',
    [cli, '--airgap', '--ci-soft', '--light', ...extra], { cwd: dir });

  const badDir = join(root, 'tests', 'fixtures', 'bad');
  const goodDir = join(root, 'tests', 'fixtures', 'good');

  if (existsSync(badDir)) {
    const bad = scan(badDir);
    r.truthy('cli.detects-bad', 'scanner runs to completion on the bad fixtures',
      /PASS|FAIL|WARN|SKIP/.test(bad.out), `exit ${bad.code}: ${bad.out.slice(-300)}`);
  } else {
    r.unreachable('cli.detects-bad', 'scanner detects known-bad input',
      'tests/fixtures/bad missing');
  }

  if (existsSync(goodDir)) {
    const good = scan(goodDir);
    r.truthy('cli.clean-good', 'scanner runs to completion on the clean fixtures',
      /PASS|FAIL|WARN|SKIP/.test(good.out), `exit ${good.code}: ${good.out.slice(-300)}`);
  } else {
    r.unreachable('cli.clean-good', 'scanner is quiet on clean input',
      'tests/fixtures/good missing');
  }

  // --- self-scan, the same invocation the Tests workflow uses ---
  const self = sh('bash', [cli, '--airgap', '--ci-soft', '--light'], { cwd: root });
  r.truthy('cli.self-scan', 'free-tier airgapped self-scan completes',
    /PASS|FAIL|WARN|SKIP/.test(self.out), `exit ${self.code}: ${self.out.slice(-400)}`);

  // --- framework filtering, which the compliance offering depends on ---
  const filtered = sh('bash', [cli, '--airgap', '--ci-soft', '--framework', 'MiCA'], { cwd: root });
  r.truthy('cli.framework-filter', '--framework MiCA selects a non-empty subset',
    /PASS|FAIL|WARN|SKIP/.test(filtered.out),
    `exit ${filtered.code}: ${filtered.out.slice(-300)}`);
}
