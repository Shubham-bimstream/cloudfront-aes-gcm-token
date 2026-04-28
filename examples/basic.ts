import { randomBytes } from 'node:crypto';
import { TokenSigner } from '../src/index.js';

const signer = new TokenSigner({
  keys: [{ version: 1, key: randomBytes(32) }],
  defaultTtlSeconds: 24 * 60 * 60,
});

const token = signer.sign({
  resource: 'documents/site-42/inspection.pdf',
  user: 'sha256-of-userid',
  tenant: 'sha256-of-companyid',
  type: 'document',
  scope: 'read',
});

console.log('Token:', token);
console.log('Length:', token.length, 'chars');

const result = signer.verify(token);
if (result.ok) {
  console.log('Verified.');
  console.log('Payload:', result.payload);
  console.log('Signed with key version:', result.keyVersion);
} else {
  console.error('Rejected:', result.reason);
  process.exit(1);
}
