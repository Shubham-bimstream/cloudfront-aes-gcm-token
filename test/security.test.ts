import { describe, expect, it } from 'vitest';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { TokenSigner } from '../src/index.js';
import { base64UrlDecode, base64UrlEncode, decode } from '../src/codec.js';

const k1 = randomBytes(32);
const k2 = randomBytes(32);

function tamper(token: string, mutate: (b: Buffer) => void): string {
  const buf = base64UrlDecode(token);
  if (!buf) throw new Error('test setup: token is not base64url');
  mutate(buf);
  return base64UrlEncode(buf);
}

const signer = new TokenSigner({
  keys: [{ version: 1, key: k1 }],
  now: () => 1_700_000_000,
});

describe('Tampering — single-bit mutations are rejected', () => {
  it('flipping the first ciphertext byte is detected', () => {
    const token = signer.sign({ resource: 'doc', ttlSeconds: 60 });
    const parts = decode(token);
    expect(parts).not.toBeNull();
    const ciphertextOffset = 1 + parts!.nonce.length;
    const tampered = tamper(token, (b) => {
      b[ciphertextOffset] ^= 0x01;
    });
    expect(signer.verify(tampered)).toEqual({ ok: false, reason: 'tampered' });
  });

  it('flipping a tag byte is detected', () => {
    const token = signer.sign({ resource: 'doc', ttlSeconds: 60 });
    const tampered = tamper(token, (b) => {
      b[b.length - 1] ^= 0x01;
    });
    expect(signer.verify(tampered)).toEqual({ ok: false, reason: 'tampered' });
  });

  it('flipping a nonce byte is detected', () => {
    const token = signer.sign({ resource: 'doc', ttlSeconds: 60 });
    const tampered = tamper(token, (b) => {
      b[1] ^= 0x01;
    });
    expect(signer.verify(tampered)).toEqual({ ok: false, reason: 'tampered' });
  });

  it('changing the key-version byte to a known but wrong key is detected via AAD', () => {
    const rotated = new TokenSigner({
      keys: [
        { version: 1, key: k1 },
        { version: 2, key: k2 },
      ],
      now: () => 1_700_000_000,
    });
    const tokenV1 = new TokenSigner({
      keys: [{ version: 1, key: k1 }],
      now: () => 1_700_000_000,
    }).sign({ resource: 'doc', ttlSeconds: 60 });

    const swapped = tamper(tokenV1, (b) => {
      b[0] = 2;
    });

    const result = rotated.verify(swapped);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('tampered');
  });
});

describe('Cross-signer isolation', () => {
  it('a token signed by one key cannot be verified by an unrelated key with the same version', () => {
    const signerA = new TokenSigner({
      keys: [{ version: 1, key: k1 }],
      now: () => 1_700_000_000,
    });
    const signerB = new TokenSigner({
      keys: [{ version: 1, key: k2 }],
      now: () => 1_700_000_000,
    });

    const token = signerA.sign({ resource: 'doc', ttlSeconds: 60 });
    expect(signerB.verify(token)).toEqual({ ok: false, reason: 'tampered' });
  });
});

describe('Malformed input', () => {
  it('rejects an empty string', () => {
    expect(signer.verify('')).toEqual({ ok: false, reason: 'malformed' });
  });

  it('rejects non-base64url input', () => {
    expect(signer.verify('not a valid token')).toEqual({ ok: false, reason: 'malformed' });
    expect(signer.verify('has=padding')).toEqual({ ok: false, reason: 'malformed' });
    expect(signer.verify('has+plus')).toEqual({ ok: false, reason: 'malformed' });
    expect(signer.verify('has/slash')).toEqual({ ok: false, reason: 'malformed' });
  });

  it('rejects a token shorter than the minimum header', () => {
    const tooShort = base64UrlEncode(Buffer.alloc(20));
    expect(signer.verify(tooShort)).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('Output sanitisation', () => {
  it('does not echo plaintext payload bytes in the token wire format', () => {
    const token = signer.sign({
      resource: 'documents/UNIQUE_MARKER_STRING_123.pdf',
      ttlSeconds: 60,
      user: 'ANOTHER_MARKER_456',
    });
    expect(token).not.toContain('UNIQUE_MARKER_STRING_123');
    expect(token).not.toContain('ANOTHER_MARKER_456');
  });
});
