# cloudfront-aes-gcm-token

Stateless AES-GCM signed asset tokens for CloudFront. Zero runtime dependencies. AES-256-GCM with first-class key rotation and a tamper-evident wire format.

[![ci](https://github.com/Shubham-bimstream/cloudfront-aes-gcm-token/actions/workflows/ci.yml/badge.svg)](https://github.com/Shubham-bimstream/cloudfront-aes-gcm-token/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why this exists

CloudFront's built-in URL signing has two practical problems for SPAs that authenticate users with cookies:

1. **Cookie-vs-URL mismatch.** CloudFront cookie signing requires one cookie set per session and breaks across subdomain boundaries. URL signing avoids cookies but the canonical query-string form leaks the resource path and a verbatim signature.
2. **Symmetric without authenticated encryption.** Rolling your own HMAC token is one wrong constant-time check away from a forgery vector. AES-GCM gives you both confidentiality and authenticity in a primitive that's been deployed for two decades.

This library encodes a JSON payload as a stateless **AES-GCM-encrypted** token, base64url-safe, with key version baked into the format so you can rotate. The token is opaque on the wire, tamper-evident, and contains everything the verifier needs to authorize the request — no DB lookup.

The pattern is common in multi-tenant asset-delivery setups behind a CDN, where a JWT in the `Authorization` header isn't an option (raw CDN byte-serves) and signed query strings leak too much information.

## Install

```bash
npm install cloudfront-aes-gcm-token
```

Requires Node 18+.

## Quickstart

```ts
import { TokenSigner } from 'cloudfront-aes-gcm-token';
import { randomBytes } from 'node:crypto';

const signer = new TokenSigner({
  keys: [{ version: 1, key: randomBytes(32) }],
  defaultTtlSeconds: 24 * 60 * 60,
});

const token = signer.sign({
  resource: 'documents/site-42/inspection.pdf',
  user: 'sha256-of-userid',
  tenant: 'sha256-of-tenantid',
  type: 'document',
  scope: 'read',
});
// → "AbcDef...base64url..."

const result = signer.verify(token);
if (result.ok) {
  // result.payload.resource, .expiresAt, .user, .tenant, .type, .scope
  // result.keyVersion → which key signed this token
} else {
  // result.reason: 'malformed' | 'unknown_key' | 'tampered' | 'expired'
}
```

Use the token as a path segment behind CloudFront:

```
https://assets.your-domain.com/protected/<token>
```

A small Lambda@Edge or origin verifier reads the path, calls `signer.verify()`, and either signs an S3 GetObject or returns 403.

## Token wire format

```
+------+----------+----------------+--------+
| 1 B  | 12 B     | N B            | 16 B   |
| ver  | nonce    | ciphertext     | tag    |
+------+----------+----------------+--------+
        \________________ AES-GCM __________/

Whole thing base64url-encoded (no padding, URL-safe).
```

- **Version byte (1 B):** key generation. Lets you rotate without invalidating outstanding tokens — the verifier looks up the key by version, the signer always emits with the active version.
- **Nonce (12 B):** randomly generated per token. Required by GCM; never reused with the same key.
- **Ciphertext (N B):** AES-256-GCM encryption of `JSON.stringify(payload)`.
- **Auth tag (16 B):** GCM tag. Any single-bit mutation of any of the three fields above causes verification to fail with `tampered`.
- **AAD:** the version byte is bound into the GCM additional-authenticated-data, so swapping the version byte to point at a different key is also rejected with `tampered`.

## Payload shape

```ts
type TokenPayload = {
  resource: string;     // S3 key or asset path
  expiresAt: number;    // Unix seconds (signer-side: now + ttl)
  user?: string;        // opaque caller-supplied identifier (you should hash before passing)
  tenant?: string;      // opaque tenant identifier
  type?: string;        // free-form asset/type tag
  scope?: string;       // free-form permission/scope tag
};
```

The library never inspects `user`, `tenant`, `type`, or `scope` — it only round-trips them. **Hash IDs before passing them in** if you don't want them recoverable by anyone holding the key.

## Key rotation

```ts
// Phase 1 — only v1 exists, all tokens signed with v1.
new TokenSigner({ keys: [{ version: 1, key: k1 }] });

// Phase 2 — v2 added, v1 still accepted. New tokens signed with v2.
new TokenSigner({
  keys: [
    { version: 1, key: k1 },
    { version: 2, key: k2 },
  ],
  // activeKeyVersion defaults to max(versions); explicit if you need otherwise.
});

// Phase 3 — once all v1-issued tokens have expired, drop v1.
new TokenSigner({ keys: [{ version: 2, key: k2 }] });
```

The rotation window equals the longest TTL you've ever issued. If you sign 24h tokens, 24h after retiring v1 the tokens are gone — drop v1 from the verifier.

## API

```ts
class TokenSigner {
  constructor(opts: SignerOptions);
  sign(opts: SignOptions): string;
  verify(token: string): VerifyResult;
}

type SignerOptions = {
  keys: KeyMaterial[];          // 1 or more
  activeKeyVersion?: number;    // default: max(keys[].version)
  defaultTtlSeconds?: number;   // default: 86400
  now?: () => number;           // default: () => Math.floor(Date.now() / 1000)
};

type SignOptions = {
  resource: string;
  ttlSeconds?: number;          // default: defaultTtlSeconds
  user?: string;
  tenant?: string;
  type?: string;
  scope?: string;
};

type VerifyResult =
  | { ok: true; payload: TokenPayload; keyVersion: number }
  | { ok: false; reason: 'malformed' | 'unknown_key' | 'tampered' | 'expired' };
```

## Threat model

**What this library protects against**

- Tampering with the token (any single-bit flip → `tampered`).
- Forging a token without the key.
- Reading the payload without the key (resource paths and IDs are opaque).
- Replaying a token with a swapped version byte to point at a different key (rejected via AAD).

**What this library does NOT protect against**

- **Replay before expiry.** A token is bearer-grade. Anyone who captures it before `expiresAt` can use it. Mitigations: short TTLs (default 24h, recommend ≤1h for sensitive assets); deliver tokens over TLS only; bind tokens to client IP / user-agent at the verifier if needed (out of scope here).
- **Clock skew between signer and verifier.** Both sides trust their own `Date.now()`. Run NTP.
- **Compromised keys.** If a key leaks, every token signed under that version is forgeable. Rotate by adding a new version and dropping the old one once outstanding tokens expire.
- **Quantum.** AES-256 is post-quantum-acceptable for data confidentiality (Grover ⇒ ~128-bit effective security), but if your threat model includes "harvest-now-decrypt-later" against signed asset URLs, this library isn't the right tool. (For most asset-signing use cases — TTLs of hours — it's fine.)

## Operational notes

- Generate keys with `crypto.randomBytes(32)` (or AWS KMS `GenerateDataKey` and store the plaintext in Secrets Manager). Don't derive them from a passphrase.
- Keep the signer and the verifier in sync via Secrets Manager rotation; the version byte makes the rotation safe.
- For Lambda@Edge verifiers, cache the `TokenSigner` instance across invocations to avoid re-parsing keys on every request.
- Token length scales with payload size. A typical payload (resource path + 4 hashed IDs + type + scope) lands around 230 base64url characters — well within URL-length limits.
- `verify()` is constant-time with respect to the key (Node's GCM implementation handles this); the `malformed` and `unknown_key` paths are not constant-time, but they're driven by attacker-controlled bytes that don't reveal anything sensitive.

## Examples

- [`examples/basic.ts`](examples/basic.ts) — sign + verify roundtrip.
- [`examples/express.ts`](examples/express.ts) — Express endpoints for `/sign` and `/protected/:token`.

```bash
npm install
npm run example:basic
npm run example:express
```

## Tests

```bash
npm test
```

The test suite covers happy-path roundtrip, every `VerifyFailReason`, single-bit tampering on every wire-format field, AAD-bound version-byte swaps, key rotation across signer instances, expiry boundary conditions, and constructor argument validation.

## License

MIT — see [LICENSE](LICENSE).
