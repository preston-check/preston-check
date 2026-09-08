/**
 * Licence issuance — the artefact a paying customer receives.
 *
 * Until now only the rejection paths of /license were asserted, because
 * LICENSE_SIGNING_KEY was never set, so generateLicenseFile() and its Ed25519
 * signing never executed at all.
 *
 * This suite issues a real licence from the Worker and then verifies it with
 * lib/license.sh — the CLI's own verifier, driven through openssl — rather
 * than re-implementing the check in JavaScript. Re-implementing it would pass
 * happily while the two sides disagreed on armour, payload encoding or the
 * bytes actually signed, which is precisely the failure this is here to catch.
 */

import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { req } from '../lib/harness.mjs';

const jsonPost = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

/** Run the CLI's own licence loader and report what it concluded. */
function verifyWithCli(root, licenceText, publicPem) {
  const dir = mkdtempSync(join(tmpdir(), 'qg-lic-'));
  const licPath = join(dir, 'license');
  const pubPath = join(dir, 'saas_pub.pem');
  writeFileSync(licPath, licenceText);
  writeFileSync(pubPath, publicPem);

  try {
    // PRESTON_PUBKEY must point at a real key that simply does not match:
    // load_license() returns early with "public key not found" if the operator
    // key is absent, so a non-existent path never reaches the SaaS branch at
    // all. The shipped operator key is the honest choice — it mirrors
    // production, where that key exists but cannot verify a SaaS-issued licence.
    const out = execFileSync('bash', ['-c', `
      set -uo pipefail
      SCRIPT_DIR="${root}"
      export PRESTON_LICENSE="${licPath}"
      export PRESTON_PUBKEY="${root}/lib/license_pubkey.pem"
      export PRESTON_PUBKEY_SAAS="${pubPath}"
      source "${root}/lib/license.sh"
      load_license
      echo "valid=\${LICENSE_VALID:-false}"
      echo "tier=\${LICENSE_TIER:-none}"
      echo "error=\${LICENSE_ERROR:-}"
    `], { stdio: 'pipe' }).toString();

    const get = (k) => (out.match(new RegExp(`^${k}=(.*)$`, 'm')) || [, ''])[1].trim();
    return { valid: get('valid'), tier: get('tier'), error: get('error') };
  } catch (e) {
    return { valid: 'false', tier: 'none', error: `cli invocation failed: ${e.message.split('\n')[0]}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export async function run(r, worker, root, publicPem) {
  r.suite('Licence issuance (billing /license → lib/license.sh)');
  const base = worker.base;

  // cs_test_qg_completed is returned by the Stripe mock as a completed session
  // with a subscription, which is the only state that may yield a licence.
  const resp = await req(base, '/license', jsonPost({ session_id: 'cs_test_qg_completed' }));
  r.status('billing.license.ok', 'completed checkout issues a licence', resp, 200);

  const disposition = resp.headers.get('content-disposition') || '';
  r.contains('billing.license.ok', 'served as a file attachment', disposition, 'attachment');
  r.contains('billing.license.ok', 'filename carries the customer id', disposition, '.license');

  const licence = await resp.text().catch(() => '');
  r.contains('billing.license.ok', 'licence carries the payload block',
    licence, '-----BEGIN PRESTON-CHECK LICENSE-----');
  r.contains('billing.license.ok', 'licence carries the signature block',
    licence, '-----BEGIN PRESTON-CHECK SIGNATURE-----');

  // The contract that matters: the CLI must accept what the Worker issued.
  const verdict = verifyWithCli(root, licence, publicPem);
  r.equal('billing.license.ok', 'CLI verifier accepts the issued licence',
    verdict.valid, 'true');
  r.equal('billing.license.ok', 'CLI reads the tier as pro', verdict.tier, 'pro');
  if (verdict.valid !== 'true') {
    r.record('billing.license.ok', 'CLI reported no verification error', false, verdict.error);
  }

  // A licence whose payload has been edited must fail the signature check.
  // Without this the assertion above would pass against a verifier that never
  // actually checks anything.
  const tampered = licence.replace(
    /-----BEGIN PRESTON-CHECK LICENSE-----\n([\s\S]*?)\n-----END/,
    (m, body) => m.replace(body, Buffer.from(
      JSON.stringify({
        license_id: 'PC-2026-FORGED', customer_id: 'cus_forged',
        customer_email: 'attacker@example.com', tier: 'enterprise',
        issued_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
        schema_version: 1,
      })).toString('base64')));
  const tamperVerdict = verifyWithCli(root, tampered, publicPem);
  r.equal('billing.license.ok', 'a tampered payload is rejected', tamperVerdict.valid, 'false');
}
