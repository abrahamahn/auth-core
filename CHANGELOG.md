# Changelog

All notable changes to this project will be documented in this file. The project follows Semantic
Versioning while allowing breaking API changes during the `0.x` series.

## Unreleased

### Fixed

- OAuth token responses now reject malformed or overflowing expiry fields instead of silently
  treating affected credentials as having no expiry, with matching TypeScript and Rust behavior.
- TypeScript WebAuthn ceremony storage now validates its injected clock and rejects expiry
  overflow before storing state.
- Rust WebAuthn now includes a single-process, single-use ceremony-state store with checked expiry
  arithmetic and consume-before-verify semantics matching the TypeScript contract.
- Repeated full-password patterns can no longer gain an authoritative score from length alone.
- Crack-time feedback now reflects pattern penalties instead of displaying raw character-set math.
- Common and repeated password values produce explicit validation failures in both languages.

### Added

- TypeScript and Rust password assessment primitives.
- Refresh-credential rotation, retry, expiration, and reuse decisions.
- Session binding, lifetime, idle, state, and eviction decisions.
- Account lockout and progressive-delay decisions.
- Shared cross-language behavior vectors and package-artifact verification.
- Generic TypeScript and Rust RBAC role inheritance and permission decisions.
- Expiring TypeScript and Rust replay guards for short-lived authentication challenges.
- Independently packaged TypeScript and Rust TOTP providers with shared RFC 6238 vectors,
  enrollment URIs, clock-window verification, and recovery-code formatting.
- Independently packaged Node.js and Rust cryptographic adapters for opaque credentials,
  scrypt/AES-256-GCM protected-secret envelopes, and domain-separated device fingerprints.
- Independently packaged Node.js and Rust Argon2 password adapters with dummy-hash timing
  resistance and shared PHC verification vectors.
- Independently packaged Node.js and Rust HS256 JWT adapters with expiration validation,
  current/previous-secret rotation, and shared signed-token vectors.
- A framework-neutral TypeScript HTTP adapter for bounded request metadata, cookie contracts, and
  coarse device labels.
- Storage, audit, notification, OAuth, and WebAuthn port contracts in the TypeScript core.
- Cross-language HMAC signing, AES-GCM cookie protection, and constant-time double-submit
  validation for CSRF tokens, preserving Ganbate's existing wire formats.
- Independently packaged Node.js and Rust OAuth adapters for Google, GitHub, Kakao, and Apple with
  normalized token/identity contracts, credentialed refresh, PKCE, generic protected state, Apple
  client assertions, and verified Apple identity tokens.
- Cross-language one-time credential acceptance, expiry, consumption, and attempt-exhaustion
  decisions plus typed, immutable, secret-safe authentication audit events.
- Independently packaged Node.js and Rust WebAuthn relying-party adapters for passkey registration
  and authentication, strict origin/RP validation, single-use ceremony state, browser-response
  normalization, and persistence-neutral credential results.
- Cross-language MFA factor selection, assurance derivation, freshness-aware step-up policy, and
  decoded challenge claim decisions, while leaving enabled factors and product policy to callers.
