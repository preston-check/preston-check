/**
 * Deployment invariants.
 *
 * These assert properties of the repository itself rather than of a running
 * service. The important one is inv.deploy-workflows-gated: it verifies that
 * every workflow which can reach production still depends on this gate. That
 * makes the gate self-defending — deleting it from a deploy workflow fails the
 * gate, so the bypass cannot land quietly.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/** Every workflow that can put artefacts or code in front of a user. */
export const DEPLOY_WORKFLOWS = [
  'pages.yml',
  'admin-pages.yml',
  'customer-pages.yml',
  'auth-deploy.yml',
  'billing-deploy.yml',
  'telemetry-deploy.yml',
  'release.yml',
];

const GATE_WORKFLOW = '.github/workflows/quality-gate.yml';

/** Parse workflow YAML via python3+pyyaml — already a CI dependency. */
function loadWorkflow(root, file) {
  const out = execFileSync('python3', ['-c', `
import yaml, json, sys
d = yaml.safe_load(open(sys.argv[1]))
jobs = d.get('jobs') or {}
print(json.dumps({
  name: {'uses': j.get('uses'), 'needs': j.get('needs'), 'if': j.get('if')}
  for name, j in jobs.items()
}))
`, join(root, '.github/workflows', file)], { stdio: 'pipe' }).toString();
  return JSON.parse(out);
}

export async function run(r, root) {
  r.suite('Deployment invariants');

  // --- 1. The test-only Stripe seam must never appear in deployed config ---
  const leaks = [];
  for (const f of ['workers/billing/wrangler.toml', 'workers/auth/wrangler.toml',
                   'workers/telemetry/wrangler.toml', 'workers/get/wrangler.toml']) {
    const p = join(root, f);
    if (existsSync(p) && readFileSync(p, 'utf8').includes('STRIPE_API_BASE')) leaks.push(f);
  }
  for (const f of DEPLOY_WORKFLOWS) {
    const p = join(root, '.github/workflows', f);
    if (existsSync(p) && readFileSync(p, 'utf8').includes('STRIPE_API_BASE')) leaks.push(f);
  }
  r.record('inv.no-stripe-api-base-in-deployed-config',
    'STRIPE_API_BASE appears in no deployed config',
    leaks.length === 0,
    leaks.length ? `would redirect live payment traffic: ${leaks.join(', ')}` : null);

  // --- 2. No live secrets committed ---
  // Matches a key SHAPE, not a bare prefix: docs legitimately write
  // "sk_live_..." when telling an operator what to paste, and a check that
  // fires on those gets muted, which is how the real one gets missed.
  //
  // Preston-Check is a secret scanner, so it necessarily ships realistic fake
  // credentials as detection material. Those paths are excluded by design:
  //   tests/fixtures/  — bad samples the scanner is asserted against
  //   corpus/          — positive/negative corpora used to compute TPR/FPR
  //                      (e.g. AWS's own AKIAIOSFODNN7EXAMPLE)
  // Excluding them keeps this check quiet enough to stay trusted; a check that
  // cries wolf on its own test data gets muted, and that is how a real leak
  // eventually slips past.
  const secretPatterns = [
    ['sk_live_[A-Za-z0-9]{20,}', 'Stripe live secret key'],
    ['rk_live_[A-Za-z0-9]{20,}', 'Stripe live restricted key'],
    ['whsec_[A-Za-z0-9]{28,}', 'Stripe webhook signing secret'],
    ['-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', 'private key'],
    ['AKIA[0-9A-Z]{16}', 'AWS access key id'],
  ];
  const found = [];
  for (const [pattern, label] of secretPatterns) {
    try {
      const hits = execFileSync('git', [
        'grep', '-lE', pattern, '--', '.',
        ':(exclude)tests/fixtures/*',
        ':(exclude)tests/quality-gate/*',
        ':(exclude)corpus/*',
      ], { cwd: root, stdio: 'pipe' }).toString().trim();
      if (hits) found.push(`${label} in ${hits.split('\n').join(', ')}`);
    } catch {
      // git grep exits 1 when there are no matches — the good case.
    }
  }
  r.record('inv.no-secrets-in-repo', 'no live secrets committed to the repo',
    found.length === 0, found.join('; ') || null);

  // --- 3. Every deploy workflow depends on this gate ---
  const ungated = [];
  if (!existsSync(join(root, GATE_WORKFLOW))) {
    ungated.push('quality-gate.yml itself is missing');
  } else {
    for (const file of DEPLOY_WORKFLOWS) {
      const p = join(root, '.github/workflows', file);
      if (!existsSync(p)) { ungated.push(`${file} (not found)`); continue; }

      let jobs;
      try { jobs = loadWorkflow(root, file); }
      catch (e) { ungated.push(`${file} (unparseable: ${e.message.split('\n')[0]})`); continue; }

      // Jobs that ARE gates rather than jobs that need gating. test.yml counts:
      // it is a verification step (release.yml calls it for the CLI), so it
      // must not be treated as an ungated deploying job.
      const isGateCall = (j) => /quality-gate\.yml|test\.yml/.test(j.uses || '');
      const gateJobs = Object.entries(jobs).filter(([, j]) => isGateCall(j)).map(([name]) => name);

      const callsQualityGate = Object.values(jobs).some(j => (j.uses || '').includes('quality-gate.yml'));
      if (!callsQualityGate) { ungated.push(`${file} (never calls the gate)`); continue; }

      // Calling the gate is not enough — every other job must depend on it,
      // directly or transitively. Compute the closure of gated jobs.
      const toArray = (v) => Array.isArray(v) ? v : (v ? [v] : []);
      const gated = new Set(gateJobs);
      for (let changed = true; changed;) {
        changed = false;
        for (const [name, j] of Object.entries(jobs)) {
          if (gated.has(name)) continue;
          if (toArray(j.needs).some(n => gated.has(n))) { gated.add(name); changed = true; }
        }
      }
      const notGated = Object.keys(jobs).filter(n => !gated.has(n));
      if (notGated.length) {
        ungated.push(`${file} jobs not gated: ${notGated.join(', ')}`);
      }
    }
  }
  r.record('inv.deploy-workflows-gated',
    `all ${DEPLOY_WORKFLOWS.length} deploy workflows depend on the quality gate`,
    ungated.length === 0,
    ungated.join(' | ') || null);

  // --- 4. A release must be gated on tests for what it actually ships ---
  // This gate covers the Workers and front ends. release.yml ships the CLI,
  // lib/ and the checks, which no suite here touches — so it must additionally
  // depend on test.yml. Asserted separately from inv.deploy-workflows-gated
  // because that one is satisfied by the quality gate alone, which would leave
  // the shipped artefact untested.
  let releaseProblem = null;
  try {
    const jobs = loadWorkflow(root, 'release.yml');
    const cliTestJobs = Object.entries(jobs)
      .filter(([, j]) => (j.uses || '').includes('test.yml'))
      .map(([name]) => name);

    if (cliTestJobs.length === 0) {
      releaseProblem = 'release.yml never calls test.yml — the CLI it ships is untested';
    } else {
      const rel = jobs['release'];
      const needs = Array.isArray(rel?.needs) ? rel.needs : (rel?.needs ? [rel.needs] : []);
      if (!needs.some(n => cliTestJobs.includes(n))) {
        releaseProblem = `release.yml calls test.yml but the release job does not need it (needs: ${needs.join(', ') || 'none'})`;
      }
    }
  } catch (e) {
    releaseProblem = `could not parse release.yml: ${e.message.split('\n')[0]}`;
  }
  r.record('inv.release-gated-on-cli-tests',
    'release.yml depends on the tests for the CLI it ships',
    releaseProblem === null, releaseProblem);
}
