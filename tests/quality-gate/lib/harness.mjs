/**
 * Quality-gate assertion harness.
 *
 * Every assertion is tagged with a surface id from surface.json. The runner
 * cross-checks the set of ids actually asserted against the inventory, so
 * "100% coverage" is a computed fact rather than a claim in a README.
 *
 * Deliberately dependency-free: Node 20 built-ins only. A gate that must
 * `npm install` before it can refuse a deploy is a gate that gets skipped
 * the first time the registry is slow.
 */

const RESET = '\x1b[0m', RED = '\x1b[31m', GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m', DIM = '\x1b[2m', BOLD = '\x1b[1m';

export class Results {
  constructor() {
    this.passed = [];
    this.failed = [];
    this.covered = new Set();
    this.currentSuite = '(none)';
  }

  suite(name) {
    this.currentSuite = name;
    process.stdout.write(`\n${BOLD}▸ ${name}${RESET}\n`);
  }

  /** Record a pass/fail against a surface id. */
  record(id, description, ok, detail) {
    this.covered.add(id);
    if (ok) {
      this.passed.push({ id, description });
      process.stdout.write(`  ${GREEN}PASS${RESET} ${DIM}${id}${RESET} ${description}\n`);
    } else {
      this.failed.push({ id, description, detail, suite: this.currentSuite });
      process.stdout.write(`  ${RED}FAIL${RESET} ${DIM}${id}${RESET} ${description}\n`);
      if (detail) process.stdout.write(`       ${RED}${detail}${RESET}\n`);
    }
  }

  /** Assert an HTTP response status, tagged with a surface id. */
  status(id, description, response, expected) {
    const ok = response.status === expected;
    this.record(id, description, ok,
      ok ? null : `expected HTTP ${expected}, got ${response.status}`);
    return ok;
  }

  equal(id, description, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    this.record(id, description, ok,
      ok ? null : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    return ok;
  }

  truthy(id, description, value, detail) {
    const ok = Boolean(value);
    this.record(id, description, ok, ok ? null : (detail || `expected truthy, got ${JSON.stringify(value)}`));
    return ok;
  }

  contains(id, description, haystack, needle) {
    const ok = typeof haystack === 'string' && haystack.includes(needle);
    this.record(id, description, ok,
      ok ? null : `expected to contain ${JSON.stringify(needle)}`);
    return ok;
  }

  /** A surface id that could not be exercised. Always a failure — never a skip. */
  unreachable(id, description, why) {
    this.record(id, description, false, `could not exercise: ${why}`);
  }

  get ok() { return this.failed.length === 0; }
}

export function banner(text) {
  process.stdout.write(`\n${BOLD}${'═'.repeat(72)}\n${text}\n${'═'.repeat(72)}${RESET}\n`);
}

export function warn(text) {
  process.stdout.write(`${YELLOW}! ${text}${RESET}\n`);
}

export function info(text) {
  process.stdout.write(`${DIM}  ${text}${RESET}\n`);
}

/** fetch with a hard timeout — a hung worker must fail the gate, not hang CI. */
export async function req(base, path, opts = {}, timeoutMs = 15000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetch(`${base}${path}`, { ...opts, signal: ctl.signal, redirect: 'manual' });
  } finally {
    clearTimeout(timer);
  }
}

export async function json(response) {
  try { return await response.json(); } catch { return null; }
}

export const sleep = (ms) => new Promise(r => setTimeout(r, ms));
