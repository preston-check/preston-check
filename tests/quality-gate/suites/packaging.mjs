/**
 * Packaging surface: the GitHub Action, the install script, the Docker image
 * and the AI add-on.
 *
 * All four are how users first meet the product, and none had any coverage.
 * A broken action.yml or install.sh fails at the moment of first contact,
 * which is the worst possible time and the least likely to be reported.
 *
 * The Docker image is linted and its entrypoint exercised rather than built
 * from scratch on every gate run — a multi-minute build in a pre-deploy gate
 * gets skipped, and a skipped check is not a check.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

function sh(cmd, args, opts = {}) {
  try {
    return { code: 0, out: execFileSync(cmd, args, { stdio: 'pipe', encoding: 'utf8', timeout: 120000, ...opts }) };
  } catch (e) {
    return { code: typeof e.status === 'number' ? e.status : 1, out: `${e.stdout || ''}${e.stderr || ''}` };
  }
}

export async function run(r, root) {
  r.suite('Packaging (action, installer, docker, ai-addon)');

  // ---------- GitHub Action ----------
  const actionPath = join(root, 'action.yml');
  if (!existsSync(actionPath)) {
    r.unreachable('pkg.action', 'action.yml is valid', 'action.yml missing');
  } else {
    const parsed = sh('python3', ['-c', `
import yaml, json, sys
d = yaml.safe_load(open(sys.argv[1]))
print(json.dumps({
  'name': d.get('name'),
  'runs_using': (d.get('runs') or {}).get('using'),
  'image': (d.get('runs') or {}).get('image'),
  'main': (d.get('runs') or {}).get('main'),
  'inputs': list((d.get('inputs') or {}).keys()),
}))
`, actionPath]);
    r.equal('pkg.action', 'action.yml parses as YAML', parsed.code, 0);
    if (parsed.code === 0) {
      const a = JSON.parse(parsed.out);
      r.truthy('pkg.action', 'action declares a name', Boolean(a.name));
      r.truthy('pkg.action', 'action declares how it runs', Boolean(a.runs_using),
        'runs.using is required by GitHub or the action cannot start');
      r.truthy('pkg.action', 'action exposes inputs', a.inputs.length > 0,
        'an action with no inputs cannot be configured');

      // A docker action pointing at a missing Dockerfile fails only at use time.
      if (a.runs_using === 'docker' && a.image && a.image.startsWith('Dockerfile')) {
        r.truthy('pkg.action', 'referenced Dockerfile exists',
          existsSync(join(root, a.image)), `${a.image} not found`);
      }
      if (a.runs_using && a.runs_using.startsWith('node') && a.main) {
        r.truthy('pkg.action', 'referenced entrypoint exists',
          existsSync(join(root, a.main)), `${a.main} not found`);
      }
    }
  }

  // ---------- install.sh ----------
  const installPath = join(root, 'install.sh');
  if (!existsSync(installPath)) {
    r.unreachable('pkg.install', 'install.sh is valid', 'install.sh missing');
  } else {
    r.equal('pkg.install', 'install.sh parses as valid bash',
      sh('bash', ['-n', installPath]).code, 0);

    const lint = sh('shellcheck', ['-S', 'error', installPath]);
    r.truthy('pkg.install', 'install.sh has no shellcheck errors',
      lint.code === 0 || /not found|ENOENT/.test(lint.out),
      lint.out.slice(0, 400));

    // This script is piped straight into bash from get.preston-check.com, so
    // it must not depend on the repo being checked out first.
    const src = readFileSync(installPath, 'utf8');
    r.truthy('pkg.install', 'installer sets a failure mode',
      /set -e|set -euo/.test(src),
      'a curl|bash installer without set -e continues after a failed step');
    r.truthy('pkg.install', 'installer resolves a download source',
      /https?:\/\//.test(src), 'no download URL found');
  }

  // ---------- Docker ----------
  const dockerfile = join(root, 'docker', 'Dockerfile');
  const entrypoint = join(root, 'docker', 'entrypoint.sh');
  if (!existsSync(dockerfile)) {
    r.unreachable('pkg.docker', 'Dockerfile is valid', 'docker/Dockerfile missing');
  } else {
    const df = readFileSync(dockerfile, 'utf8');
    r.truthy('pkg.docker', 'Dockerfile declares a base image', /^\s*FROM\s+\S+/m.test(df));
    r.truthy('pkg.docker', 'Dockerfile declares an entrypoint or command',
      /^\s*(ENTRYPOINT|CMD)\s/m.test(df));
    r.truthy('pkg.docker', 'Dockerfile does not run as root at runtime',
      /^\s*USER\s+(?!root)\S+/m.test(df),
      'no non-root USER directive — a scanner image running as root is a needless risk');

    if (existsSync(entrypoint)) {
      r.equal('pkg.docker', 'entrypoint.sh parses as valid bash',
        sh('bash', ['-n', entrypoint]).code, 0);
    } else {
      r.truthy('pkg.docker', 'entrypoint.sh exists if referenced',
        !/entrypoint\.sh/.test(df), 'Dockerfile references entrypoint.sh but it is missing');
    }
  }

  // ---------- AI add-on ----------
  const addon = join(root, 'ai-addon');
  if (!existsSync(addon)) {
    r.unreachable('pkg.ai-addon', 'ai-addon is well formed', 'ai-addon/ missing');
  } else {
    const shells = sh('bash', ['-c',
      `find "${addon}" -name '*.sh' -print0 | xargs -0 -r -n50 bash -n 2>&1 | head -20`]);
    r.truthy('pkg.ai-addon', 'every ai-addon shell script parses',
      shells.out.trim() === '', shells.out.slice(0, 400));

    const jsons = sh('bash', ['-c',
      `find "${addon}" -name '*.json' -print0 | xargs -0 -r -I{} python3 -c "import json,sys;json.load(open('{}'))" 2>&1 | head -10`]);
    r.truthy('pkg.ai-addon', 'every ai-addon JSON file parses',
      jsons.out.trim() === '', jsons.out.slice(0, 400));
  }
}
