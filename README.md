# auth-core

`auth-core` is a modular authentication foundation. Its pure TypeScript and Rust core packages own
password assessment, session and refresh-credential decisions, account lockout, reusable RBAC
mechanics, and short-lived challenge replay protection. Separate provider packages own optional
authentication mechanisms without pulling their dependencies into the pure core.

It deliberately does not own product role names or permission assignments, HTTP route mounting,
database schemas, eligibility, terms, notification wording, user profiles, or application
configuration. Applications keep those policies and adapt their facts into reusable packages.

- [`typescript/`](typescript/) — npm package `@abrahamahn/auth-core`
- [`rust/`](rust/) — Rust crate `auth-core`
- [`typescript-totp/`](typescript-totp/) — npm package `@abrahamahn/auth-totp`
- [`rust-totp/`](rust-totp/) — Rust crate `auth-totp`
- [`rust/fixtures/`](rust/fixtures/) — shared cross-language behavior vectors

## Cross-language contract

Both core implementations expose the same deterministic decisions using language-idiomatic names
and types. The shared vectors pin password outcomes, refresh rotation and reuse, session binding,
credential epochs, session lifetime and eviction, idle handling, progressive delay, and account
lockout. The TOTP packages share RFC 6238 vectors across TypeScript and Rust.

## Ganbate extraction boundary

Ganbate delegates password assessment, session calculations, refresh-credential decisions, account
lockout, RBAC inheritance, challenge replay protection, and TOTP provider behavior to this
repository. Code intentionally left in Ganbate falls into these adapter or product categories:

- Argon2, JWT, OAuth, and WebAuthn integrations not yet represented by a dedicated package;
- HTTP routes, request/response schemas, cookies, and middleware;
- database queries, transactions, repositories, audit persistence, and notifications;
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
