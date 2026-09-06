/**
 * Boots a Worker under `wrangler dev --local` (workerd + real local D1/KV),
 * seeds its D1 schema, waits for readiness, and tears it down.
 *
 * Running the real runtime rather than importing handlers with hand-written
 * D1/KV fakes is deliberate: the fakes are what stop catching schema drift,
 * SQL typos and binding-name mistakes — exactly the class of defect that only
 * shows up in production.
 */

import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { info, warn, sleep } from './harness.mjs';

// Pinned, not floating: the gate's verdict must not change because npm
// published a new wrangler overnight. Bump deliberately. The pin must be new
// enough to support the compatibility_date in every wrangler.toml — 4.86
// refuses "2026-05-04" and the gate correctly fails rather than skipping.
const WRANGLER = ['--yes', 'wrangler@4.129.0'];

function dbNameFrom(wranglerToml) {
  const m = readFileSync(wranglerToml, 'utf8').match(/database_name\s*=\s*"([^"]+)"/);
  return m ? m[1] : null;
}

export class Worker {
  constructor(root, spec, name) {
    this.root = root;
    this.spec = spec;
    this.name = name;
    this.dir = join(root, spec.dir);
    this.port = spec.port;
    this.base = `http://127.0.0.1:${spec.port}`;
    this.proc = null;
    this.persist = null;
    this.logPath = null;
  }

  /** Apply schema.sql into an isolated local D1 so each run starts clean. */
  seed() {
    this.persist = mkdtempSync(join(tmpdir(), `qg-${this.name}-`));
    if (!this.spec.schema) return;

    const schemaPath = join(this.root, this.spec.schema);
    const toml = join(this.dir, 'wrangler.toml');
    if (!existsSync(schemaPath) || !existsSync(toml)) {
      throw new Error(`${this.name}: missing schema or wrangler.toml`);
    }
    const db = dbNameFrom(toml);
    if (!db) throw new Error(`${this.name}: no database_name in wrangler.toml`);

    execFileSync('npx', [
      ...WRANGLER, 'd1', 'execute', db,
      '--local', '--file', schemaPath, '--persist-to', this.persist, '-y',
    ], { cwd: this.dir, stdio: 'pipe', env: { ...process.env, CI: '1' } });
    info(`${this.name}: D1 schema applied (${db})`);
  }

  /** Start wrangler dev. `vars` become env.* inside the Worker. */
  async start(vars = {}) {
    const args = [
      ...WRANGLER, 'dev',
      '--local',
      '--port', String(this.port),
      '--inspector-port', String(this.port + 100),
      '--persist-to', this.persist,
    ];
    for (const [k, v] of Object.entries(vars)) args.push('--var', `${k}:${v}`);

    this.logPath = join(this.persist, 'wrangler.log');
    const out = (await import('node:fs')).openSync(this.logPath, 'a');
    // detached so the whole npx→wrangler→workerd tree can be killed as a
    // process group; killing only npx orphans workerd holding the port.
    this.proc = spawn('npx', args, {
      cwd: this.dir,
      stdio: ['ignore', out, out],
      detached: true,
      env: { ...process.env, CI: '1', WRANGLER_SEND_METRICS: 'false' },
    });

    for (let i = 0; i < 60; i++) {
      if (await this.alive()) {
        info(`${this.name}: ready on ${this.base}`);
        return;
      }
      if (this.proc.exitCode !== null) break;
      await sleep(1000);
    }
    throw new Error(`${this.name}: did not become ready.\n${this.tail()}`);
  }

  async alive() {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 1500);
      // OPTIONS is handled by every worker and mutates nothing.
      await fetch(`${this.base}/`, { method: 'OPTIONS', signal: ctl.signal });
      clearTimeout(t);
      return true;
    } catch { return false; }
  }

  tail(n = 25) {
    try {
      return readFileSync(this.logPath, 'utf8').split('\n').slice(-n).join('\n');
    } catch { return '(no wrangler log)'; }
  }

  /** Read rows straight out of the local D1, to prove writes really landed. */
  query(sql) {
    const toml = join(this.dir, 'wrangler.toml');
    const db = dbNameFrom(toml);
    try {
      const out = execFileSync('npx', [
        ...WRANGLER, 'd1', 'execute', db,
        '--local', '--command', sql, '--persist-to', this.persist, '--json', '-y',
      ], { cwd: this.dir, stdio: 'pipe', env: { ...process.env, CI: '1' } }).toString();
      const parsed = JSON.parse(out.slice(out.indexOf('[')));
      return parsed?.[0]?.results ?? [];
    } catch (e) {
      warn(`${this.name}: D1 query failed: ${e.message.split('\n')[0]}`);
      return [];
    }
  }

  /**
   * Read a KV value from the local namespace. Used to pull the issued sign-in
   * code so the verify-code happy path is exercised end to end. Reading real
   * KV state rather than scraping the log keeps this deterministic — the log
   * line is written by a fire-and-forget console.log with no flush guarantee.
   */
  kvGet(binding, key) {
    try {
      const out = execFileSync('npx', [
        ...WRANGLER, 'kv', 'key', 'get', key,
        '--binding', binding, '--local', '--persist-to', this.persist, '--text',
      ], { cwd: this.dir, stdio: 'pipe', env: { ...process.env, CI: '1' } }).toString();
      return out.trim();
    } catch {
      return null;
    }
  }

  stop() {
    if (this.proc) {
      try { process.kill(-this.proc.pid, 'SIGKILL'); } catch { }
      try { this.proc.kill('SIGKILL'); } catch { }
      this.proc = null;
    }
    if (this.persist) {
      try { rmSync(this.persist, { recursive: true, force: true }); } catch { }
    }
  }
}
