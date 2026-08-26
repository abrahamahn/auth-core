# Changelog

All notable changes to this project will be documented in this file. The project follows Semantic
Versioning while allowing breaking API changes during the `0.x` series.

## Unreleased

### Fixed

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
