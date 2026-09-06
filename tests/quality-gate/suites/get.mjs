/**
 * Install-redirect Worker acceptance suite (get.preston-check.com).
 *
 * This Worker is the front door for `curl -fsSL https://get.preston-check.com/
 * install.sh | bash`. If it regresses, first-touch installs break silently, so
 * both the proxy and the catch-all redirect are asserted.
 *
 * /install.sh proxies the real GitHub release, so this suite needs network.
 * That is deliberate: the value of the assertion is that the upstream release
 * asset is actually reachable and is actually a shell script.
 */

import { req } from '../lib/harness.mjs';

export async function run(r, worker) {
  r.suite('Install redirect Worker (workers/get)');
  const base = worker.base;

  const sh = await req(base, '/install.sh', { method: 'GET' }, 30000);
  r.status('get.install-sh', 'install.sh is served', sh, 200);
  r.contains('get.install-sh', 'served as a shell script',
    sh.headers.get('content-type') || '', 'shellscript');
  r.equal('get.install-sh', 'marked as sourced from the GitHub release',
    sh.headers.get('x-source'), 'github-release');

  const body = await sh.text().catch(() => '');
  r.truthy('get.install-sh', 'body looks like a shell script',
    body.includes('#!/') || body.includes('set -e'),
    `first 80 chars: ${JSON.stringify(body.slice(0, 80))}`);

  const redirect = await req(base, '/anything', { method: 'GET' });
  r.status('get.redirect', 'unknown path redirects', redirect, 302);
  r.contains('get.redirect', 'redirects to the releases page',
    redirect.headers.get('location') || '', '/releases/latest');
}
