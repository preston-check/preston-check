/**
 * Rendered front-end acceptance suite.
 *
 * Loads every page in a real headless Chromium — not a string search over the
 * HTML. A page can contain all the right markup and still be broken: a syntax
 * error in app.js, a stylesheet that 404s, an uncaught exception on init. Only
 * an actual render catches those.
 *
 * External API calls are blocked at the network layer so pages are judged on
 * their own behaviour. A page that throws an uncaught exception because its
 * backend is unreachable is a page with unhandled failure paths, and the gate
 * treats that as a defect rather than an environment problem.
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { cpSync, mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, extname, normalize, dirname } from 'node:path';
import { info } from '../lib/harness.mjs';

/**
 * Reproduce the directory the deploy workflow publishes. Serving the source
 * tree instead would 404 on ../landing/assets/* in the test while production
 * resolves them fine — a gate that fails on correct code teaches people to
 * ignore it.
 */
function stageApp(root, app) {
  if (!app.stage) return join(root, app.root);
  const out = mkdtempSync(join(tmpdir(), 'qg-fe-'));
  for (const [src, dest] of app.stage) {
    const from = join(root, src), to = join(out, dest);
    if (!existsSync(from)) continue;
    mkdirSync(dirname(to), { recursive: true });
    cpSync(from, to, { recursive: true });
  }
  return out;
}

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2',
};

/** Static file server rooted at a front-end directory. */
function serve(rootDir, port) {
  const server = createServer(async (req, res) => {
    // normalize + strip leading separators: no traversal out of rootDir.
    const rel = normalize(decodeURIComponent((req.url || '/').split('?')[0]))
      .replace(/^(\.\.[/\\])+/, '').replace(/^[/\\]+/, '');
    const file = join(rootDir, rel || 'index.html');
    try {
      const buf = await readFile(file);
      res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
      res.end(buf);
    } catch {
      res.writeHead(404); res.end('not found');
    }
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () =>
    resolve({ base: `http://127.0.0.1:${port}`, close: () => new Promise(r => server.close(r)) })));
}

async function loadPlaywright(r, ids) {
  try {
    return (await import('playwright')).chromium;
  } catch {
    // Never a skip: an unrenderable front end must fail the gate, or the
    // "rendered" half of this gate silently stops existing.
    for (const id of ids) {
      r.unreachable(id, 'page renders in a real browser',
        'playwright is not installed — run: npm i -D playwright && npx playwright install chromium');
    }
    return null;
  }
}

export async function run(r, root, frontends, apps) {
  r.suite('Rendered front ends (as deployed)');

  const chromium = await loadPlaywright(r, frontends.map(f => f.id));
  if (!chromium) return;

  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const servers = new Map();
  const staged = [];
  let port = 8850;

  try {
    for (const fe of frontends) {
      if (!servers.has(fe.app)) {
        const dir = stageApp(root, apps[fe.app]);
        if (apps[fe.app].stage) staged.push(dir);
        info(`${fe.app}: serving deployed layout from ${dir}`);
        servers.set(fe.app, await serve(dir, port++));
      }
      const srv = servers.get(fe.app);

      const context = await browser.newContext();
      const page = await context.newPage();

      const pageErrors = [];
      const badAssets = [];
      page.on('pageerror', e => pageErrors.push(e.message));
      page.on('response', resp => {
        const u = resp.url();
        if (u.startsWith(srv.base) && resp.status() >= 400) {
          badAssets.push(`${resp.status()} ${u.replace(srv.base, '')}`);
        }
      });
      // Block anything off-origin so the verdict is about this page only.
      await page.route('**', route =>
        route.request().url().startsWith(srv.base) ? route.continue() : route.abort());

      const resp = await page.goto(`${srv.base}/${fe.page}`, {
        waitUntil: 'domcontentloaded', timeout: 20000,
      });
      // Let deferred scripts run and any init settle.
      await page.waitForTimeout(600);

      r.truthy(fe.id, `${fe.app}/${fe.page} responds 200`,
        resp && resp.status() === 200, `status ${resp && resp.status()}`);

      r.truthy(fe.id, `${fe.app}/${fe.page} renders without uncaught exceptions`,
        pageErrors.length === 0, pageErrors.join(' | '));

      r.truthy(fe.id, `${fe.app}/${fe.page} loads all local assets`,
        badAssets.length === 0, badAssets.join(', '));

      // Actually rendered, not merely present in the markup.
      const text = await page.evaluate(() => document.body.innerText || '');
      for (const needle of fe.requires) {
        r.contains(fe.id, `${fe.page} renders visible text "${needle}"`, text, needle);
      }

      const visible = await page.evaluate(() => {
        const b = document.body;
        return b && b.getBoundingClientRect().height > 100;
      });
      r.truthy(fe.id, `${fe.page} paints a non-trivial body`, visible,
        'rendered body height <= 100px — page is probably blank');

      await context.close();
    }
  } finally {
    await browser.close();
    for (const s of servers.values()) await s.close();
    for (const dir of staged) { try { rmSync(dir, { recursive: true, force: true }); } catch { } }
    info('front-end servers closed, staged dirs removed');
  }
}
