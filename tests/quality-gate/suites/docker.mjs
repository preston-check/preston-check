/**
 * The published Docker image — built and actually run, not just linted.
 *
 * Linting the Dockerfile proves it parses. It does not prove the image builds,
 * that the entrypoint resolves, that the checks are executable inside the
 * image, or that a scan produces anything. Those are the failures a user hits
 * on `docker run`, and they were all invisible to the gate until now.
 *
 * The build is the expensive part of the gate (~2-4 min). That cost was
 * accepted deliberately: a broken image otherwise reaches users, and the
 * packaging suite's static checks cannot catch it.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { info } from '../lib/harness.mjs';

const TAG = 'preston-check:quality-gate';

function sh(cmd, args, opts = {}) {
  try {
    return { code: 0, out: execFileSync(cmd, args, {
      stdio: 'pipe', encoding: 'utf8', timeout: 600000, ...opts,
    }) };
  } catch (e) {
    return {
      code: typeof e.status === 'number' ? e.status : 1,
      out: `${e.stdout || ''}${e.stderr || ''}`,
    };
  }
}

export async function run(r, root) {
  r.suite('Docker image (built and run)');

  if (sh('docker', ['info']).code !== 0) {
    // Never a silent skip: an unverifiable image must fail the gate, or the
    // most user-visible artefact quietly stops being covered.
    r.unreachable('pkg.docker-image', 'the image builds and scans',
      'the Docker daemon is not reachable — start Docker and re-run');
    return;
  }

  // --- build ---
  info('building the image (this is the slow part of the gate)');
  const build = sh('docker', ['build', '-t', TAG, '-f', 'docker/Dockerfile', '.'], { cwd: root });
  const built = r.truthy('pkg.docker-image', 'image builds from docker/Dockerfile',
    build.code === 0, build.out.split('\n').slice(-12).join('\n'));
  if (!built) return;

  try {
    // --- the default CMD works ---
    const help = sh('docker', ['run', '--rm', TAG, '--help']);
    r.truthy('pkg.docker-image', 'default entrypoint responds to --help',
      help.out.includes('Usage:'), `exit ${help.code}: ${help.out.slice(-300)}`);

    // --- it does not run as root ---
    // Asserted from the running container, not from a USER line in the
    // Dockerfile: a later layer or a --user default could still change it.
    const who = sh('docker', ['run', '--rm', '--entrypoint', 'id', TAG, '-un']);
    r.equal('pkg.docker-image', 'container runs as the unprivileged preston user',
      who.out.trim(), 'preston');

    // --- a real scan over a mounted source tree ---
    // This is the documented usage from the Dockerfile header, and the only
    // assertion that proves the checks are present and executable inside the
    // image rather than merely copied in.
    const work = mkdtempSync(join(tmpdir(), 'qg-docker-'));
    writeFileSync(join(work, 'sample.java'),
      'public class A {\n  private static final String k = "sk_live_1234567890abcdef1234567890abcdef";\n}\n');
    try {
      const scan = sh('docker', [
        'run', '--rm', '-v', `${work}:/src`, TAG, '--airgap', '--ci-soft', '--light',
      ]);
      r.truthy('pkg.docker-image', 'a scan runs to completion inside the image',
        /PASS|FAIL|WARN|SKIP/.test(scan.out),
        `exit ${scan.code}: ${scan.out.slice(-400)}`);
      r.truthy('pkg.docker-image', 'the scan reports check results, not an empty run',
        (scan.out.match(/PASS|FAIL|WARN|SKIP/g) || []).length > 5,
        `only ${(scan.out.match(/PASS|FAIL|WARN|SKIP/g) || []).length} result markers seen`);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }

    // --- the optional entrypoint wrapper ---
    // Users wire this in CI to inject a licence from a secret; if it stopped
    // working, paid tiers would silently fall back to free inside containers.
    const wrapper = sh('docker', [
      'run', '--rm', '--entrypoint', '/bin/bash', TAG, '-n',
      '/opt/preston-check/tools/tap-push.sh',
    ]);
    r.equal('pkg.docker-image', 'shipped tools/ scripts parse inside the image',
      wrapper.code, 0);
  } finally {
    sh('docker', ['image', 'rm', '-f', TAG]);
    info('image removed');
  }
}
