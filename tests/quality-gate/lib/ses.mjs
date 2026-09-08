/**
 * SES v2 test double that independently re-derives the SigV4 signature.
 *
 * The auth Worker hand-rolls SigV4 because aws-sdk-js would not fit in a
 * Worker. Nothing exercised it: with no credentials configured the Worker
 * always took the "manual log" branch, so the signing code shipped untested.
 *
 * The mock recomputes the signature from the request it received, using the
 * documented algorithm and the known test secret, and compares. This is
 * deliberately an independent implementation rather than a call back into the
 * Worker's own helpers — a shared implementation would agree with itself even
 * when both sides are wrong. Same shape as the Stripe webhook check, with the
 * direction reversed: there the test signs and the Worker verifies.
 */

import { createHmac, createHash } from 'node:crypto';
import { createServer } from 'node:http';

export const SES_KEY_ID = 'AKIAQUALITYGATEKEY00';
export const SES_SECRET = 'quality-gate-fake-ses-secret-key-000000';
export const SES_REGION = 'us-east-1';
export const SES_HOST = `email.${SES_REGION}.amazonaws.com`;
const SES_PATH = '/v2/email/outbound-emails';

const sha256Hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const hmac = (key, data) => createHmac('sha256', key).update(data, 'utf8').digest();

/** Re-derive the expected Authorization value for a received request. */
function expectedAuthorization({ body, amzDate, dateStamp }) {
  const payloadHash = sha256Hex(body);
  const canonicalHeaders =
    `content-type:application/json\nhost:${SES_HOST}\n` +
    `x-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = [
    'POST', SES_PATH, '', canonicalHeaders, signedHeaders, payloadHash,
  ].join('\n');

  const scope = `${dateStamp}/${SES_REGION}/ses/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest),
  ].join('\n');

  const kDate = hmac(`AWS4${SES_SECRET}`, dateStamp);
  const kRegion = hmac(kDate, SES_REGION);
  const kService = hmac(kRegion, 'ses');
  const kSigning = hmac(kService, 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');

  return `AWS4-HMAC-SHA256 Credential=${SES_KEY_ID}/${scope}, ` +
         `SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

export function startSesMock(port) {
  const received = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      const amzDate = req.headers['x-amz-date'] || '';
      const record = {
        path: req.url,
        authorization: req.headers['authorization'] || '',
        amzDate,
        contentSha: req.headers['x-amz-content-sha256'] || '',
        body,
        signatureValid: false,
        expected: null,
      };
      if (/^\d{8}T\d{6}Z$/.test(amzDate)) {
        record.expected = expectedAuthorization({ body, amzDate, dateStamp: amzDate.slice(0, 8) });
        record.signatureValid = record.expected === record.authorization;
      }
      received.push(record);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ MessageId: 'qg-message-id-0001' }));
    });
  });

  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve({
    base: `http://127.0.0.1:${port}`,
    received,
    close: () => new Promise(r => server.close(r)),
  })));
}
