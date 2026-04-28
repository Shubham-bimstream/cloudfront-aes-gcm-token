export type SignOptions = {
  resource: string;
  ttlSeconds?: number;
  user?: string;
  tenant?: string;
  type?: string;
  scope?: string;
};

export type TokenPayload = {
  resource: string;
  expiresAt: number;
  user?: string;
  tenant?: string;
  type?: string;
  scope?: string;
};

export type KeyMaterial = {
  version: number;
  key: Buffer;
};

export type SignerOptions = {
  keys: KeyMaterial[];
  activeKeyVersion?: number;
  defaultTtlSeconds?: number;
  now?: () => number;
};

export type VerifyFailReason =
  | 'malformed'
  | 'unknown_key'
  | 'tampered'
  | 'expired';

export type VerifyResult =
  | { ok: true; payload: TokenPayload; keyVersion: number }
  | { ok: false; reason: VerifyFailReason };
