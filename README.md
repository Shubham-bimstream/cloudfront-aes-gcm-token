# cloudfront-aes-gcm-token

Small Node library for opaque, stateless AES-GCM asset tokens — designed to ride in URL path segments behind a CDN, verified by Lambda@Edge or an origin service. Zero runtime dependencies, first-class key rotation, tamper-evident wire format.

[![ci](https://github.com/Shubham-bimstream/cloudfront-aes-gcm-token/actions/workflows/ci.yml/badge.svg)](https://github.com/Shubham-bimstream/cloudfront-aes-gcm-token/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Status: 0.1.x — experimental.** This is a security-sensitive utility. The underlying primitive (AES-256-GCM via Node's built-in `crypto`) is rock solid; the *packaging* in this library has not been independently reviewed. Audit the code, threat-model your use case, and treat this as a *starting point*, not a turnkey production crypto layer.

## What this is — and isn't

This is **one** valid pattern for protecting CDN-fronted assets, alongside several others. Most teams should reach for the standard tools first:

| Pattern | Resource path confidentiality | Verifier | Key rotation | When to use |
|---|---|---|---|---|
| **CloudFront signed URL** | ❌ visible in query string | CloudFront edge | Manual key-pair swap | The default. Time-boxed single-asset delivery. |
| **CloudFront signed cookie** | ❌ visible in cookie scope | CloudFront edge | Manual key-pair swap | Authenticated-session asset access on a single domain. |
| **JWT in `Authorization` header** | ❌ claims base64-decodable | App / API gateway | Standard | API auth. Not designed to live in a URL path. |
| **HMAC token in URL** | ❌ no encryption | Origin compares MAC | Manual | When you don't need payload confidentiality. Watch for non-constant-time-compare bugs. |
| **This library** | ✅ encrypted | Lambda@Edge / origin decrypts | Built into wire format | Narrow case below. |

This library is for the narrower case where **all** of the following hold:

1. The resource path or token payload itself is sensitive — e.g. multi-tenant SaaS where `documents/<tenant>/<asset>` shouldn't appear verbatim in a signed query string.
2. You want user / tenant / scope encoded in the token and recoverable by the verifier without a DB hop.
3. You're fronting bytes with CloudFront and run a verifier in **Lambda@Edge** or at the origin (CloudFront Functions don't have the crypto APIs needed for AES-GCM — this won't run there).
4. You want first-class key rotation as part of the wire format.

If your case is "I want to give one user a temporary download link," use a CloudFront signed URL. Don't reach for this.

## When to use

- ✅ Multi-tenant asset delivery where the resource path leaks tenant boundaries.
- ✅ CDN-fronted byte serves where a JWT in the `Authorization` header isn't an option.
- ✅ You need user / tenant / scope encoded in the token, verifier-decryptable, no DB hop.
- ✅ You want a tamper-evident bearer token with built-in key rotation.
- ✅ You have a Lambda@Edge or origin verifier in your auth path.

## When NOT to use

- ❌ Your use case fits CloudFront signed URLs or cookies — use those.
- ❌ You need general API authentication — OAuth + JWT is the right shape.
- ❌ Your verifier needs to run in **CloudFront Functions** — no AES-GCM API there. Use Lambda@Edge instead, or pick a different design.
- ❌ You need audited, compliance-grade crypto infrastructure — this is 0.x experimental code, not a substitute for a reviewed security library.
- ❌ One-time single-user file delivery — a signed URL is simpler and doesn't need a verifier service.
- ❌ You're using this for *authentication* rather than *authorization to fetch a specific asset* — bearer tokens that live in URLs are fundamentally weaker than tokens in headers.

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
- Reading the payload without the key (resource paths and IDs are opaque on the wire).
- Replaying a token with a swapped version byte to point at a different key (rejected via AAD).

**What this library does NOT protect against**

- **Replay before expiry.** A token is bearer-grade. Anyone who captures it before `expiresAt` can use it. Mitigations: short TTLs (default 24h, recommend ≤1h for sensitive assets); deliver tokens over TLS only; bind tokens to client IP / user-agent at the verifier if needed (out of scope here).
- **Clock skew between signer and verifier.** Both sides trust their own `Date.now()`. Run NTP.
- **Compromised keys.** If a key leaks, every token signed under that version is forgeable. Rotate by adding a new version and dropping the old once outstanding tokens expire.
- **Quantum.** AES-256 is post-quantum-acceptable for data confidentiality (Grover ⇒ ~128-bit effective security), but if your threat model includes "harvest-now-decrypt-later" against signed asset URLs, this library isn't the right tool.
- **Side channels.** Node's GCM implementation handles the cipher's constant-time concerns, but nothing here defends against timing analysis at the verifier layer beyond what the cipher provides.
- **Use as session auth.** Tokens encode authorization to fetch a specific resource for a window of time. They are not a session, not a refresh token, and not a substitute for proper authentication.

## Operational notes

- Generate keys with `crypto.randomBytes(32)` (or AWS KMS `GenerateDataKey` and store the plaintext in Secrets Manager). Don't derive them from a passphrase.
- Keep the signer and the verifier in sync via Secrets Manager rotation; the version byte makes the rotation safe.
- For Lambda@Edge verifiers, cache the `TokenSigner` instance across invocations to avoid re-parsing keys on every request.
- Token length scales with payload size. A typical payload (resource path + 4 hashed IDs + type + scope) lands around 230 base64url characters — well within URL-length limits.

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

## Contributing

This is a small library and the surface area is intentional. Issues and PRs welcome for: documentation clarity, additional examples (Lambda@Edge skeleton, Cloudflare Workers via Web Crypto), security-relevant test cases, and platform support beyond Node 18+. **Please don't open PRs that broaden the cipher choices, change the wire format, or add features outside the "opaque asset token" use case** — there are better libraries for those.

## License

MIT — see [LICENSE](LICENSE).
