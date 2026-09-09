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
import { mkdtempSync, rmSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
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

  /**
   * Locate miniflare's backing SQLite for a storage kind ("d1" or "kv").
   * Layout: <persist>/v3/<kind>/miniflare-<X>Object/<hash>.sqlite, with
   * metadata.sqlite alongside it.
   */
  _storeDbs(kind, objectDir) {
    const dir = join(this.persist, 'v3', kind, objectDir);
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter(n => n.endsWith('.sqlite') && !n.startsWith('metadata'))
      .map(n => join(dir, n));
  }

  /**
   * Read rows straight out of the local D1, to prove writes really landed.
   *
   * Reads miniflare's SQLite directly rather than shelling out to
   * `wrangler d1 execute`. A second wrangler process against a --persist-to
   * directory that `wrangler dev` is already serving kills the dev server:
   * on macOS the very next request dies with ECONNRESET, which is how the
   * auth suite failed on the first local run. Direct reads also avoid paying
   * an npx startup per assertion.
   */
  query(sql) {
    const files = this._storeDbs('d1', 'miniflare-D1DatabaseObject');
    if (!files.length) { warn(`${this.name}: no local D1 store found`); return []; }
    // Opened read-write: a few suites seed fixture rows through here. SQLite
    // is in WAL mode, so this coexists with the running Worker's reads.
    let db;
    try {
      db = new DatabaseSync(files[0]);
      const stmt = db.prepare(sql);
      return /^\s*(select|with|pragma)/i.test(sql) ? stmt.all() : (stmt.run(), []);
    } catch (e) {
      warn(`${this.name}: D1 query failed: ${String(e.message).split('\n')[0]}`);
      return [];
    } finally {
      try { db?.close(); } catch { }
    }
  }

  /**
   * Read a KV value from the local namespace. Used to pull the issued sign-in
   * code so the verify-code happy path is exercised end to end. Reading real
   * KV state rather than scraping the log keeps this deterministic — the log
   * line is written by a fire-and-forget console.log with no flush guarantee.
   *
   * miniflare stores the key index in `_mf_entries` and the value in a blob
   * file under v3/kv/<namespace>/blobs/<blob_id>. Read directly, for the same
   * reason as query(): spawning wrangler here resets the live dev server.
   */
  kvGet(binding, key) {
    for (const file of this._storeDbs('kv', 'miniflare-KVNamespaceObject')) {
      let db;
      try {
        db = new DatabaseSync(file, { readOnly: true });
        const row = db.prepare(
          'SELECT blob_id, expiration FROM _mf_entries WHERE key = ?'
        ).get(key);
        if (!row) continue;
        // Honour TTL: an expired entry is absent as far as the Worker is
        // concerned, so the harness must not report it as present.
        if (row.expiration && Number(row.expiration) <= Date.now()) continue;

        const kvRoot = join(this.persist, 'v3', 'kv');
        for (const ns of readdirSync(kvRoot)) {
          const blob = join(kvRoot, ns, 'blobs', row.blob_id);
          if (existsSync(blob)) return readFileSync(blob, 'utf8');
        }
      } catch {
        // try the next namespace store
      } finally {
        try { db?.close(); } catch { }
      }
    }
    return null;
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
