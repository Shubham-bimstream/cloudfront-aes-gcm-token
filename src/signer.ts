import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { decode, encode, NONCE_BYTES } from './codec.js';
import type {
  KeyMaterial,
  SignerOptions,
  SignOptions,
  TokenPayload,
  VerifyResult,
} from './types.js';

const ALGO = 'aes-256-gcm';
const KEY_BYTES = 32;
const DEFAULT_TTL_SECONDS = 24 * 60 * 60;

export class TokenSigner {
  private readonly keys: Map<number, Buffer>;
  private readonly activeKeyVersion: number;
  private readonly defaultTtlSeconds: number;
  private readonly now: () => number;

  constructor(opts: SignerOptions) {
    if (opts.keys.length === 0) {
      throw new Error('TokenSigner: at least one key is required');
    }

    this.keys = new Map();
    for (const k of opts.keys) {
      validateKey(k);
      if (this.keys.has(k.version)) {
        throw new Error(`TokenSigner: duplicate key version ${k.version}`);
      }
      this.keys.set(k.version, k.key);
    }

    const active = opts.activeKeyVersion ?? Math.max(...this.keys.keys());
    if (!this.keys.has(active)) {
      throw new Error(`TokenSigner: activeKeyVersion ${active} not found in keys`);
    }
    this.activeKeyVersion = active;

    this.defaultTtlSeconds = opts.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  sign(opts: SignOptions): string {
    if (!opts.resource) {
      throw new Error('TokenSigner.sign: resource is required');
    }

    const ttl = opts.ttlSeconds ?? this.defaultTtlSeconds;
    if (!Number.isInteger(ttl) || ttl <= 0) {
      throw new Error('TokenSigner.sign: ttlSeconds must be a positive integer');
    }

    const payload: TokenPayload = {
      resource: opts.resource,
      expiresAt: this.now() + ttl,
      ...(opts.user !== undefined ? { user: opts.user } : {}),
      ...(opts.tenant !== undefined ? { tenant: opts.tenant } : {}),
      ...(opts.type !== undefined ? { type: opts.type } : {}),
      ...(opts.scope !== undefined ? { scope: opts.scope } : {}),
    };

    const key = this.keys.get(this.activeKeyVersion);
    if (!key) {
      throw new Error('TokenSigner.sign: active key missing (invariant)');
    }

    const nonce = randomBytes(NONCE_BYTES);
    const aad = Buffer.from([this.activeKeyVersion]);
    const cipher = createCipheriv(ALGO, key, nonce);
    cipher.setAAD(aad);

    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return encode({
      keyVersion: this.activeKeyVersion,
      nonce,
      ciphertext,
      tag,
    });
  }

  verify(token: string): VerifyResult {
    const parts = decode(token);
    if (parts === null) return { ok: false, reason: 'malformed' };

    const key = this.keys.get(parts.keyVersion);
    if (!key) return { ok: false, reason: 'unknown_key' };

    let plaintext: Buffer;
    try {
      const decipher = createDecipheriv(ALGO, key, parts.nonce);
      decipher.setAAD(Buffer.from([parts.keyVersion]));
      decipher.setAuthTag(parts.tag);
      plaintext = Buffer.concat([decipher.update(parts.ciphertext), decipher.final()]);
    } catch {
      return { ok: false, reason: 'tampered' };
    }

    let payload: TokenPayload;
    try {
      payload = JSON.parse(plaintext.toString('utf8')) as TokenPayload;
    } catch {
      return { ok: false, reason: 'tampered' };
    }

    if (
      typeof payload?.resource !== 'string' ||
      typeof payload?.expiresAt !== 'number' ||
      !Number.isFinite(payload.expiresAt)
    ) {
      return { ok: false, reason: 'tampered' };
    }

    if (payload.expiresAt <= this.now()) {
      return { ok: false, reason: 'expired' };
    }

    return { ok: true, payload, keyVersion: parts.keyVersion };
  }
}

function validateKey(k: KeyMaterial): void {
  if (!Number.isInteger(k.version) || k.version < 0 || k.version > 255) {
    throw new Error(
      `TokenSigner: key version must be an integer in [0, 255], got ${k.version}`,
    );
  }
  if (!Buffer.isBuffer(k.key) || k.key.length !== KEY_BYTES) {
    throw new Error(
      `TokenSigner: each key must be a ${KEY_BYTES}-byte Buffer (got ${
        Buffer.isBuffer(k.key) ? k.key.length + ' bytes' : typeof k.key
      })`,
    );
  }
}
