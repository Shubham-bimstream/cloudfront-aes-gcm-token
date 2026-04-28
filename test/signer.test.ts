import { describe, expect, it } from 'vitest';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { TokenSigner } from '../src/index.js';

const k1 = randomBytes(32);
const k2 = randomBytes(32);

function makeSigner(now: () => number = () => 1_700_000_000) {
  return new TokenSigner({
    keys: [{ version: 1, key: k1 }],
    now,
  });
}

describe('TokenSigner — happy path', () => {
  it('round-trips a minimal payload', () => {
    const signer = makeSigner();
    const token = signer.sign({ resource: 'documents/abc.pdf', ttlSeconds: 3600 });
    const result = signer.verify(token);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.payload.resource).toBe('documents/abc.pdf');
      expect(result.payload.expiresAt).toBe(1_700_000_000 + 3600);
      expect(result.keyVersion).toBe(1);
    }
  });

  it('round-trips a fully-populated payload', () => {
    const signer = makeSigner();
    const token = signer.sign({
      resource: 'vision/site-42/cube/0.jpg',
      ttlSeconds: 600,
      user: 'sha256-of-userid',
      tenant: 'sha256-of-companyid',
      type: 'cubemap-face',
      scope: 'read',
    });
    const result = signer.verify(token);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.payload).toMatchObject({
        resource: 'vision/site-42/cube/0.jpg',
        user: 'sha256-of-userid',
        tenant: 'sha256-of-companyid',
        type: 'cubemap-face',
        scope: 'read',
      });
    }
  });

  it('uses defaultTtlSeconds when ttlSeconds is omitted', () => {
    const signer = new TokenSigner({
      keys: [{ version: 1, key: k1 }],
      defaultTtlSeconds: 7200,
      now: () => 1_700_000_000,
    });
    const token = signer.sign({ resource: 'a' });
    const result = signer.verify(token);
    expect(result.ok && result.payload.expiresAt).toBe(1_700_000_000 + 7200);
  });

  it('emits unique tokens for the same input (random nonce)', () => {
    const signer = makeSigner();
    const a = signer.sign({ resource: 'x', ttlSeconds: 60 });
    const b = signer.sign({ resource: 'x', ttlSeconds: 60 });
    expect(a).not.toBe(b);
  });

  it('produces tokens that are URL-safe (no +, /, =)', () => {
    const signer = makeSigner();
    const token = signer.sign({ resource: 'x', ttlSeconds: 60 });
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('TokenSigner — expiry', () => {
  it('rejects an expired token', () => {
    let now = 1_700_000_000;
    const signer = new TokenSigner({ keys: [{ version: 1, key: k1 }], now: () => now });
    const token = signer.sign({ resource: 'x', ttlSeconds: 60 });
    now += 61;
    const result = signer.verify(token);
    expect(result).toEqual({ ok: false, reason: 'expired' });
  });

  it('accepts a token at the boundary just before expiry', () => {
    let now = 1_700_000_000;
    const signer = new TokenSigner({ keys: [{ version: 1, key: k1 }], now: () => now });
    const token = signer.sign({ resource: 'x', ttlSeconds: 60 });
    now += 59;
    expect(signer.verify(token).ok).toBe(true);
  });

  it('rejects a token at the exact expiry second', () => {
    let now = 1_700_000_000;
    const signer = new TokenSigner({ keys: [{ version: 1, key: k1 }], now: () => now });
    const token = signer.sign({ resource: 'x', ttlSeconds: 60 });
    now += 60;
    expect(signer.verify(token)).toEqual({ ok: false, reason: 'expired' });
  });
});

describe('TokenSigner — key rotation', () => {
  it('signs with the highest-version key by default', () => {
    const signer = new TokenSigner({
      keys: [
        { version: 1, key: k1 },
        { version: 2, key: k2 },
      ],
      now: () => 1_700_000_000,
    });
    const token = signer.sign({ resource: 'x', ttlSeconds: 60 });
    const result = signer.verify(token);
    expect(result.ok && result.keyVersion).toBe(2);
  });

  it('respects an explicit activeKeyVersion', () => {
    const signer = new TokenSigner({
      keys: [
        { version: 1, key: k1 },
        { version: 2, key: k2 },
      ],
      activeKeyVersion: 1,
      now: () => 1_700_000_000,
    });
    const token = signer.sign({ resource: 'x', ttlSeconds: 60 });
    const result = signer.verify(token);
    expect(result.ok && result.keyVersion).toBe(1);
  });

  it('verifies tokens issued by an old key after rotation', () => {
    const oldSigner = new TokenSigner({
      keys: [{ version: 1, key: k1 }],
      now: () => 1_700_000_000,
    });
    const token = oldSigner.sign({ resource: 'x', ttlSeconds: 600 });

    const rotated = new TokenSigner({
      keys: [
        { version: 1, key: k1 },
        { version: 2, key: k2 },
      ],
      activeKeyVersion: 2,
      now: () => 1_700_000_000,
    });

    const result = rotated.verify(token);
    expect(result.ok && result.keyVersion).toBe(1);
  });

  it('rejects a token whose key version was retired', () => {
    const oldSigner = new TokenSigner({
      keys: [{ version: 1, key: k1 }],
      now: () => 1_700_000_000,
    });
    const token = oldSigner.sign({ resource: 'x', ttlSeconds: 600 });

    const newSigner = new TokenSigner({
      keys: [{ version: 2, key: k2 }],
      now: () => 1_700_000_000,
    });

    expect(newSigner.verify(token)).toEqual({ ok: false, reason: 'unknown_key' });
  });
});

describe('TokenSigner — constructor validation', () => {
  it('rejects empty keys[]', () => {
    expect(() => new TokenSigner({ keys: [] })).toThrow(/at least one key/);
  });

  it('rejects a key shorter than 32 bytes', () => {
    expect(
      () => new TokenSigner({ keys: [{ version: 1, key: Buffer.alloc(16) }] }),
    ).toThrow(/32-byte Buffer/);
  });

  it('rejects a duplicate key version', () => {
    expect(
      () =>
        new TokenSigner({
          keys: [
            { version: 1, key: k1 },
            { version: 1, key: k2 },
          ],
        }),
    ).toThrow(/duplicate key version/);
  });

  it('rejects a key version outside [0, 255]', () => {
    expect(() => new TokenSigner({ keys: [{ version: 256, key: k1 }] })).toThrow(
      /\[0, 255\]/,
    );
    expect(() => new TokenSigner({ keys: [{ version: -1, key: k1 }] })).toThrow(
      /\[0, 255\]/,
    );
  });

  it('rejects an activeKeyVersion that is not in keys', () => {
    expect(
      () => new TokenSigner({ keys: [{ version: 1, key: k1 }], activeKeyVersion: 9 }),
    ).toThrow(/not found in keys/);
  });
});

describe('TokenSigner.sign — argument validation', () => {
  it('rejects an empty resource', () => {
    const signer = makeSigner();
    expect(() => signer.sign({ resource: '' })).toThrow(/resource is required/);
  });

  it('rejects a non-positive ttl', () => {
    const signer = makeSigner();
    expect(() => signer.sign({ resource: 'x', ttlSeconds: 0 })).toThrow(/positive integer/);
    expect(() => signer.sign({ resource: 'x', ttlSeconds: -1 })).toThrow(/positive integer/);
  });
});
