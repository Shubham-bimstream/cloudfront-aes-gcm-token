import { Buffer } from 'node:buffer';

export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const KEY_VERSION_BYTES = 1;
export const MIN_TOKEN_BYTES = KEY_VERSION_BYTES + NONCE_BYTES + TAG_BYTES;

export type DecodedToken = {
  keyVersion: number;
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
};

export function encode(parts: DecodedToken): string {
  const buf = Buffer.concat([
    Buffer.from([parts.keyVersion]),
    parts.nonce,
    parts.ciphertext,
    parts.tag,
  ]);
  return base64UrlEncode(buf);
}

export function decode(token: string): DecodedToken | null {
  const buf = base64UrlDecode(token);
  if (buf === null || buf.length < MIN_TOKEN_BYTES + 1) return null;

  const keyVersion = buf[0];
  if (keyVersion === undefined) return null;

  const nonce = buf.subarray(KEY_VERSION_BYTES, KEY_VERSION_BYTES + NONCE_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(KEY_VERSION_BYTES + NONCE_BYTES, buf.length - TAG_BYTES);

  if (nonce.length !== NONCE_BYTES || tag.length !== TAG_BYTES || ciphertext.length === 0) {
    return null;
  }

  return { keyVersion, nonce, ciphertext, tag };
}

export function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(input: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  const pad = (4 - (input.length % 4)) % 4;
  const padded = input + '='.repeat(pad);
  try {
    return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } catch {
    return null;
  }
}
