/**
 * Ed25519 key material for the licence path.
 *
 * The real signing key is a Worker secret nobody has locally, so the gate
 * generates a throwaway pair per run: the private half goes to the billing
 * Worker as LICENSE_SIGNING_KEY, the public half to lib/license.sh via
 * PRESTON_PUBKEY_SAAS. That lets the licence the Worker issues be verified by
 * the CLI's own verifier rather than by a reimplementation of it here — the
 * point is to test the contract between the two, not to restate it.
 */

import { generateKeyPairSync } from 'node:crypto';

export function makeLicenceKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');

  // importPrivateKey() in the Worker strips PEM armour and all whitespace, so
  // a bare one-line base64 body is accepted — and it survives `wrangler dev
  // --var KEY:VALUE`, which cannot carry newlines.
  const pkcs8B64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');

  // openssl needs a properly armoured SPKI PEM.
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  return { pkcs8B64, publicPem };
}
