# auth-core

`auth-core` provides deterministic, storage-neutral authentication security primitives. The
TypeScript and Rust packages own password assessment, session lifetime and eviction calculations,
refresh-credential classification, binding checks, credential-epoch comparisons, and account
lockout/progressive-delay decisions.

It deliberately does not implement HTTP, cookies, JWTs, OAuth providers, password hashing,
databases, email/SMS, product eligibility, user profiles, tenancy, or application authorization.
Applications keep those policies and adapt persisted facts into the core's pure decisions.

- [`typescript/`](typescript/) — npm package `@abrahamahn/auth-core`
- [`rust/`](rust/) — Rust crate `auth-core`
- [`rust/fixtures/`](rust/fixtures/) — shared cross-language behavior vectors

## Cross-language contract

Both implementations expose the same deterministic decisions using language-idiomatic names and
types. The shared vectors pin password outcomes, refresh rotation and reuse, session binding,
credential epochs, session lifetime and eviction, idle handling, progressive delay, and account
lockout. Each implementation also has focused unit tests for validation and invalid input.

## Ganbate extraction boundary

Ganbate now delegates its password assessment, session calculations, refresh-credential decisions,
and account lockout calculations to this package. Code intentionally left in Ganbate falls into one
of these adapter or product-owned categories:

- Argon2, JWT, random-token, TOTP, OAuth, and WebAuthn integrations;
- HTTP routes, request/response schemas, cookies, and middleware;
- database queries, transactions, repositories, audit persistence, and notifications;
- Ganbate roles, permissions, tenancy, terms acceptance, eligibility, and user profiles.

Those modules may be reusable as integrations, but they do not belong in this deterministic core.

## Stability

The TypeScript and Rust packages are currently `0.1.x`. Cross-language behavior is treated as one
contract, but breaking API corrections may still occur before `1.0.0` and are recorded in
[`CHANGELOG.md`](CHANGELOG.md).

Password strength and crack-time estimates are advisory. The built-in common-password list rejects
obvious online-guessing candidates, but a consuming verifier must also screen the complete proposed
password against an application-maintained common or breached-password blocklist before hashing it.

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the required TypeScript, Rust, parity, and package
validation commands. CI runs those checks independently for both language packages.
