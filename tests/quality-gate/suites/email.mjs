/**
 * E-mail delivery via SES.
 *
 * Previously unreachable: with no credentials set the Worker always fell
 * through to the "manual log" branch, so the hand-rolled SigV4 signer — the
 * riskiest code in the auth Worker — was never executed by any test.
 *
 * The auth Worker for this suite is booted with SES credentials and
 * SES_API_BASE pointing at the mock. The request is still signed for the real
 * SES host, so the signature asserted here is the one production would send.
 */

import { req, json } from '../lib/harness.mjs';

const jsonPost = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

export async function run(r, worker, ses) {
  r.suite('E-mail delivery (auth → SES SigV4)');

  const email = 'ses-gate@preston-check.com';
  const resp = await req(worker.base, '/request-code', jsonPost({ email }));
  r.status('auth.email.ses', 'request-code succeeds with SES configured', resp, 200);

  const body = await json(resp);
  r.equal('auth.email.ses', 'delivery reported as sent', body && body.sent, true);
  r.equal('auth.email.ses', 'delivery channel reported as ses', body && body.via, 'ses');

  const call = ses.received[ses.received.length - 1];
  if (!call) {
    r.record('auth.email.ses', 'SES received a send request', false,
      'no request reached the SES mock');
    return;
  }

  r.equal('auth.email.ses', 'posts to the SES v2 outbound-emails path',
    call.path, '/v2/email/outbound-emails');
  r.contains('auth.email.ses', 'authorization uses AWS4-HMAC-SHA256',
    call.authorization, 'AWS4-HMAC-SHA256');
  r.contains('auth.email.ses', 'credential scope names the ses service',
    call.authorization, `/ses/aws4_request`);
  r.contains('auth.email.ses', 'signs the real SES host, not the mock',
    call.expected || '', 'Signature=');

  // The assertion that matters: an independently derived signature agrees.
  r.truthy('auth.email.ses', 'SigV4 signature is correct',
    call.signatureValid,
    `worker sent:\n  ${call.authorization}\nindependently derived:\n  ${call.expected}`);

  // The payload hash is part of the canonical request, so a wrong one would
  // already have failed the signature check above; assert only that the header
  // is present and well formed, which is what SES itself requires.
  r.truthy('auth.email.ses', 'x-amz-content-sha256 is a sha256 digest',
    /^[a-f0-9]{64}$/.test(call.contentSha), `got ${JSON.stringify(call.contentSha)}`);

  // And the message must actually carry the code the user needs.
  const code = worker.kvGet('CODES', `code:${email}`);
  r.truthy('auth.email.ses', 'the issued code is present in the e-mail body',
    code && call.body.includes(code),
    `code ${code} not found in SES payload`);
  r.contains('auth.email.ses', 'e-mail is addressed to the requester', call.body, email);
}
