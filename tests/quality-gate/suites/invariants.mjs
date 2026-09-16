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

  // --- 1. Test-only API seams must never appear in deployed config ---
  // STRIPE_API_BASE redirects payment traffic; SES_API_BASE redirects sign-in
  // e-mails. Both default to the real endpoint and exist only so the gate can
  // exercise paths that need live credentials. Either one set in a deployed
  // config would silently divert production traffic to somewhere else.
  const SEAMS = ['STRIPE_API_BASE', 'SES_API_BASE'];
  const leaks = [];
  const configs = [
    'workers/billing/wrangler.toml', 'workers/auth/wrangler.toml',
    'workers/telemetry/wrangler.toml', 'workers/get/wrangler.toml',
    ...DEPLOY_WORKFLOWS.map(f => `.github/workflows/${f}`),
  ];
  for (const f of configs) {
    const p = join(root, f);
    if (!existsSync(p)) continue;
    const text = readFileSync(p, 'utf8');
    for (const seam of SEAMS) {
      if (text.includes(seam)) leaks.push(`${seam} in ${f}`);
    }
  }
  r.record('inv.no-stripe-api-base-in-deployed-config',
    'no test-only API seam appears in a deployed config',
    leaks.length === 0,
    leaks.length ? `would divert production traffic: ${leaks.join(', ')}` : null);

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

  // --- 5. Anything that taps or installs from our tap must trust it first ---
  // Homebrew 6.0 refuses to LOAD formulae from a non-official tap unless it is
  // trusted ($HOMEBREW_REQUIRE_TAP_TRUST, default true), and reports the
  // refusal as "Cannot tap preston-check/tap: invalid syntax in tap!" — naming
  // neither trust nor the cause, and reading like a defect in our own Ruby.
  //
  // This broke every bottle leg on all four platforms from v1.8.456 onwards
  // (Releases #486–#490) and, far worse, broke `brew install` for every user on
  // Homebrew 6.0+, because the published install instructions never mentioned
  // brew trust. Install docs ARE the product on a distribution channel: a
  // documented command that cannot work is a shipped defect, not a typo. So
  // this check covers the docs and the workflow as one category.
  const trustProblems = [];
  let tapRefs = [];
  try {
    tapRefs = execFileSync('git', [
      'grep', '-lE', 'brew (tap|install|info|untap) preston-check/tap', '--', '.',
      // Historical records and generated output must not be rewritten to
      // satisfy a check about what we tell users to run today.
      ':(exclude)CHANGELOG.md',
      ':(exclude)docs/OPEN_ITEMS.md',
      ':(exclude)docs/sessions/*',
      ':(exclude)docs/_rendered/*',
      ':(exclude)tests/quality-gate/*',
    ], { cwd: root, stdio: 'pipe' }).toString().trim().split('\n').filter(Boolean);
  } catch {
    // git grep exits 1 on no matches. Nothing references the tap at all, which
    // would itself mean the install instructions vanished.
    trustProblems.push('no file references the tap — install instructions are missing');
  }

  for (const f of tapRefs) {
    if (!/brew trust/.test(readFileSync(join(root, f), 'utf8'))) {
      trustProblems.push(`${f} tells the reader to tap/install without brew trust`);
    }
  }

  // Ordering is the part that regresses silently: `brew trust` AFTER `brew tap`
  // still reads correctly but fails, because the tap is the step being refused.
  const relPath = join(root, '.github/workflows/release.yml');
  if (existsSync(relPath)) {
    const rel = readFileSync(relPath, 'utf8');
    const trustAt = rel.indexOf('brew trust --tap preston-check/tap');
    const tapAt = rel.indexOf('brew tap preston-check/tap');
    if (trustAt === -1) {
      trustProblems.push('release.yml never trusts the tap — every bottle leg will fail');
    } else if (tapAt !== -1 && trustAt > tapAt) {
      trustProblems.push('release.yml trusts the tap AFTER tapping it — the tap is what gets refused');
    }
  }

  r.record('inv.brew-tap-trusted-before-use',
    'every documented and automated brew tap/install trusts the tap first',
    trustProblems.length === 0, trustProblems.join(' | ') || null);

  // --- 6. The platforms we build must be the platforms we verify ---
  // release.yml declares EXPECTED_BOTTLE_TAGS once; the bottle matrix builds
  // them and update-tap fails when one is missing from the published formula.
  // Two lists that must agree are exactly how a platform disappears quietly:
  // the Intel leg was removed from the matrix and nothing noticed the tap had
  // stopped carrying an Intel bottle for 15 releases. A leg added or removed
  // without touching the declaration fails here instead.
  const bottleProblems = [];
  try {
    const out = execFileSync('python3', ['-c', `
import yaml, json, sys
d = yaml.safe_load(open(sys.argv[1]))
matrix = (((d.get('jobs') or {}).get('bottle') or {}).get('strategy') or {}).get('matrix') or {}
print(json.dumps({
  'declared': ((d.get('env') or {}).get('EXPECTED_BOTTLE_TAGS') or '').split(),
  'matrix': [leg.get('bottle_tag') for leg in (matrix.get('include') or [])],
}))
`, join(root, '.github/workflows/release.yml')], { stdio: 'pipe' }).toString();
    const { declared, matrix } = JSON.parse(out);

    if (declared.length === 0) {
      bottleProblems.push('release.yml declares no EXPECTED_BOTTLE_TAGS — nothing verifies what the tap ships');
    }
    if (matrix.length === 0) {
      bottleProblems.push('release.yml has no bottle matrix legs — every platform would build from source');
    }
    const onlyMatrix = matrix.filter(t => !declared.includes(t));
    const onlyDeclared = declared.filter(t => !matrix.includes(t));
    if (onlyMatrix.length) {
      bottleProblems.push(`built but never verified: ${onlyMatrix.join(', ')}`);
    }
    if (onlyDeclared.length) {
      bottleProblems.push(`expected but never built: ${onlyDeclared.join(', ')}`);
    }

    // A declaration nothing reads is decoration. update-tap's guard must be the
    // thing consuming it, or the two lists agree while the tap goes unchecked.
    const relSrc = readFileSync(join(root, '.github/workflows/release.yml'), 'utf8');
    if (!relSrc.includes('os.environ.get("EXPECTED_BOTTLE_TAGS"')) {
      bottleProblems.push('update-tap never reads EXPECTED_BOTTLE_TAGS — the missing-bottle guard is not wired');
    }
  } catch (e) {
    bottleProblems.push(`could not parse release.yml: ${e.message.split('\n')[0]}`);
  }

  r.record('inv.bottle-tags-match-matrix',
    'the bottle platforms release.yml builds are exactly the ones it verifies were published',
    bottleProblems.length === 0, bottleProblems.join(' | ') || null);
}
