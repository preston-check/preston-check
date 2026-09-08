/**
 * The customer sign-in journey, driven in a real browser against real Workers.
 *
 * The front-end suite proves each page renders. It does not prove the funnel
 * works: 444 lines of web/customer/app.js — form wiring, requestCode,
 * verifyCode, token storage, the signed-in transition — were never executed.
 * A typo in a element id or a change to a response field would leave every
 * render assertion green while no customer could sign in.
 *
 * Here the page is served from its deployed layout with the two Worker URL
 * constants rewritten to the local instances, and those Workers are booted
 * with ALLOW_ORIGIN set to the page origin, so the browser makes genuine
 * cross-origin calls that must satisfy the real CORS headers.
 */

import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { cpSync, mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, extname } from 'node:path';
import { info } from '../lib/harness.mjs';

export const FLOW_PAGE_PORT = 8860;
export const FLOW_PAGE_ORIGIN = `http://127.0.0.1:${FLOW_PAGE_PORT}`;

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2',
};

function serve(rootDir, port) {
  const server = createServer(async (req, res) => {
    const rel = decodeURIComponent((req.url || '/').split('?')[0]).replace(/^\/+/, '') || 'index.html';
    try {
      const buf = await readFile(join(rootDir, rel));
      res.writeHead(200, { 'Content-Type': MIME[extname(rel)] || 'application/octet-stream' });
      res.end(buf);
    } catch { res.writeHead(404); res.end('not found'); }
  });
  return new Promise(r => server.listen(port, '127.0.0.1', () =>
    r({ base: `http://127.0.0.1:${port}`, close: () => new Promise(x => server.close(x)) })));
}

/** Stage the customer app, repointing its Worker constants at local instances. */
async function stageCustomer(root, app, authBase, billingBase) {
  const out = mkdtempSync(join(tmpdir(), 'qg-flow-'));
  for (const [src, dest] of app.stage) {
    const from = join(root, src), to = join(out, dest);
    if (!existsSync(from)) continue;
    mkdirSync(dirname(to), { recursive: true });
    cpSync(from, to, { recursive: true });
  }
  const appJs = join(out, 'app.js');
  const before = await readFile(appJs, 'utf8');
  const after = before
    .replace(/const AUTH_WORKER\s*=\s*'[^']*'/, `const AUTH_WORKER = '${authBase}'`)
    .replace(/const BILLING_WORKER\s*=\s*'[^']*'/, `const BILLING_WORKER = '${billingBase}'`);
  await writeFile(appJs, after);
  // If the constants ever move, the rewrite silently no-ops and the test would
  // pass against unreachable production URLs. Report that rather than hide it.
  return { dir: out, rewritten: after.includes(authBase) && after.includes(billingBase) };
}

export async function run(r, root, apps, authWorker, billingBase) {
  r.suite('Customer sign-in journey (browser → real Workers)');

  let chromium;
  try { chromium = (await import('playwright')).chromium; }
  catch {
    r.unreachable('flow.customer-signin', 'the sign-in journey completes',
      'playwright is not installed');
    return;
  }

  const staged = await stageCustomer(root, apps.customer, authWorker.base, billingBase);
  r.truthy('flow.customer-signin', 'app.js Worker constants were repointed at the test instances',
    staged.rewritten,
    'the AUTH_WORKER/BILLING_WORKER declarations no longer match the rewrite pattern');

  const srv = await serve(staged.dir, FLOW_PAGE_PORT);
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(e.message));

  const email = `flow-${Date.now()}@preston-check.com`;

  try {
    await page.goto(`${srv.base}/index.html`, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(500);

    // Unauthenticated visitors must land on the login screen.
    const loginVisible = await page.evaluate(() => {
      const el = document.getElementById('login-screen');
      return Boolean(el) && getComputedStyle(el).display !== 'none';
    });
    r.truthy('flow.customer-signin', 'an unauthenticated visitor sees the login screen', loginVisible);

    // --- step 1: request a code ---
    await page.fill('#login-email', email);
    await page.click('#login-email-form button[type=submit]').catch(async () => {
      await page.evaluate(() =>
        document.getElementById('login-email-form').dispatchEvent(new Event('submit', { cancelable: true })));
    });
    await page.waitForTimeout(1200);

    const codeFormShown = await page.evaluate(() => {
      const f = document.getElementById('login-code-form');
      return Boolean(f) && getComputedStyle(f).display !== 'none';
    });
    r.truthy('flow.customer-signin', 'submitting an e-mail advances to the code step',
      codeFormShown,
      `status said: ${await page.evaluate(() => (document.getElementById('login-status') || {}).textContent || '')}`);

    // The Worker must actually have issued a code for this address.
    const code = authWorker.kvGet('CODES', `code:${email}`);
    r.truthy('flow.customer-signin', 'the Worker issued a code for the submitted address',
      code && /^\d{6}$/.test(code), `KV held ${JSON.stringify(code)}`);

    // --- step 2: verify it ---
    if (code && /^\d{6}$/.test(code)) {
      await page.fill('#login-code', code);
      await page.click('#login-code-form button[type=submit]').catch(async () => {
        await page.evaluate(() =>
          document.getElementById('login-code-form').dispatchEvent(new Event('submit', { cancelable: true })));
      });
      await page.waitForTimeout(1500);

      const signedIn = await page.evaluate(() => {
        const el = document.getElementById('login-screen');
        return Boolean(el) && getComputedStyle(el).display === 'none';
      });
      r.truthy('flow.customer-signin', 'a correct code signs the customer in', signedIn,
        `status said: ${await page.evaluate(() => (document.getElementById('login-status') || {}).textContent || '')}`);

      // A session that is not persisted means the next page load logs them out.
      // Key taken from storeToken() in web/customer/app.js, not guessed.
      const stored = await page.evaluate(() => {
        try { return localStorage.getItem('pc_session_token') || ''; } catch { return ''; }
      });
      r.truthy('flow.customer-signin', 'the session token is persisted client-side',
        /^[a-f0-9]{64}$/.test(stored),
        `localStorage['pc_session_token'] held ${JSON.stringify(stored)}`);
    }

    r.truthy('flow.customer-signin', 'the journey raised no uncaught exceptions',
      pageErrors.length === 0, pageErrors.join(' | '));
  } finally {
    await context.close();
    await browser.close();
    await srv.close();
    rmSync(staged.dir, { recursive: true, force: true });
    info('flow: browser and page server closed');
  }
}
