# Contributing

Changes should preserve storage-neutral boundaries and matching TypeScript/Rust semantics.
Product-specific authorization policy, HTTP frameworks, and application database schemas do not
belong here. Provider SDKs and infrastructure dependencies belong in dedicated provider or adapter
packages, never in the pure `auth-core` package.

When behavior changes:

1. Add or update the shared vector in `rust/fixtures/core-vectors.json` when both languages expose
   the behavior.
2. Update both implementations in the same change.
3. Add focused success, boundary, and invalid-input tests.
4. Update `CHANGELOG.md` when the public contract changes.

## Validation

From `typescript/`:

```sh
pnpm install --frozen-lockfile
pnpm prepack
pnpm pack --dry-run
```

Run the same commands from `typescript-totp/`, `typescript-crypto-node/`,
`typescript-password-argon2/`, `typescript-jwt-node/`, `typescript-http/`,
`typescript-oauth-node/`, and `typescript-webauthn-node/`.

From `rust/`:

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo package --locked
```

Run the same commands from `rust-totp/`, `rust-crypto/`, `rust-password-argon2/`, `rust-jwt/`,
`rust-oauth/`, and `rust-webauthn/`.
