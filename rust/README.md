# auth-core

`auth-core` is a dependency-free Rust library for deterministic authentication decisions. It
matches the repository's TypeScript package across password assessment, refresh-credential
classification, session lifetime and eviction, session binding, credential epochs, account
lockout, and progressive delay.

It deliberately excludes HTTP, cookies, JWTs, password hashing, OAuth/WebAuthn providers,
persistence, product roles, authorization policy, notifications, and device presentation.

Strength and crack-time estimates are advisory. Applications must supplement the built-in common
password screening with their own current breached-password blocklist before accepting a password.

```sh
cargo build --all-targets
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo doc --no-deps
```
