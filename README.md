# auth-core

`auth-core` is a modular authentication foundation. Its pure TypeScript and Rust core packages own
password assessment, session and refresh-credential decisions, one-time credential consumption,
account lockout, MFA assurance and step-up decisions, reusable RBAC mechanics, typed secret-safe
audit events, and short-lived challenge replay protection. Separate provider packages own optional
authentication mechanisms without pulling their dependencies into the pure core.

It deliberately does not own product role names or permission assignments, HTTP route mounting,
database schemas, eligibility, terms, notification wording, user profiles, or application
configuration. Applications keep those policies and adapt their facts into reusable packages.

- [`typescript/`](typescript/) — npm package `@abrahamahn/auth-core`
- [`rust/`](rust/) — Rust crate `auth-core`
- [`typescript-totp/`](typescript-totp/) — npm package `@abrahamahn/auth-totp`
- [`rust-totp/`](rust-totp/) — Rust crate `auth-totp`
- [`typescript-crypto-node/`](typescript-crypto-node/) — npm package
  `@abrahamahn/auth-crypto-node`
- [`typescript-http/`](typescript-http/) — npm package `@abrahamahn/auth-http`
- [`rust-crypto/`](rust-crypto/) — Rust crate `auth-crypto`
- [`typescript-password-argon2/`](typescript-password-argon2/) — npm package
  `@abrahamahn/auth-password-argon2`
- [`rust-password-argon2/`](rust-password-argon2/) — Rust crate `auth-password-argon2`
- [`typescript-jwt-node/`](typescript-jwt-node/) — npm package `@abrahamahn/auth-jwt-node`
- [`rust-jwt/`](rust-jwt/) — Rust crate `auth-jwt`
- [`typescript-oauth-node/`](typescript-oauth-node/) — npm package
  `@abrahamahn/auth-oauth-node`
- [`rust-oauth/`](rust-oauth/) — Rust crate `auth-oauth`
- [`typescript-webauthn-node/`](typescript-webauthn-node/) — npm package
  `@abrahamahn/auth-webauthn-node`
- [`rust-webauthn/`](rust-webauthn/) — Rust crate `auth-webauthn`
- [`rust/fixtures/`](rust/fixtures/) — shared cross-language behavior vectors

## Cross-language contract

Both core implementations expose the same deterministic decisions using language-idiomatic names
and types. The shared vectors pin password outcomes, refresh rotation and reuse, session binding,
credential epochs, session lifetime and eviction, idle handling, progressive delay, and account
lockout, plus one-time credential acceptance and attempt exhaustion. The TOTP packages share RFC
6238 vectors across TypeScript and Rust. MFA assurance derivation and decoded challenge decisions
also share cross-language vectors. The crypto adapter packages share opaque-token digests, device
fingerprints, and a byte-compatible authenticated secret-envelope format. The Argon2 packages
share PHC verification vectors, the JWT packages share signed HS256 token vectors, and the OAuth
packages share normalized token, identity, PKCE, and protected-state contracts. The WebAuthn
packages expose language-idiomatic, standard-compatible relying-party registration/authentication
ceremonies and require single-use server-side state.

## Ganbate extraction boundary

Ganbate delegates password assessment, session calculations, refresh-credential decisions, account
lockout, one-time credential decisions, RBAC inheritance, challenge replay protection, typed audit
event contracts, MFA assurance, factor selection, decoded challenge decisions, TOTP, OAuth, and
WebAuthn provider behavior, opaque-token cryptography,
protected-secret envelopes, CSRF token protection, Argon2 password hashing, HS256 JWT rotation,
request metadata, and device labeling to this repository. Code intentionally left in Ganbate falls
into these adapter or product categories:

- HTTP route mounting, application request/response schemas, cookie policy, and middleware composition;
- database queries, transactions, credential/ceremony repositories, audit persistence, and notifications;
- Ganbate roles, permissions, tenancy, terms acceptance, eligibility, and user profiles.

Those modules may become dedicated adapters or providers, but they do not belong in the pure core.

## Stability

The packages are pre-`1.0`. Cross-language behavior is treated as one contract, but breaking API
corrections may still occur before `1.0.0` and are recorded in [`CHANGELOG.md`](CHANGELOG.md).

Password strength and crack-time estimates are advisory. The built-in common-password list rejects
obvious online-guessing candidates, but a consuming verifier must also screen the complete proposed
password against an application-maintained common or breached-password blocklist before hashing it.

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the required TypeScript, Rust, parity, and package
validation commands. CI runs those checks independently for both language packages.
