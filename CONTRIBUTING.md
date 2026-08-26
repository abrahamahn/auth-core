# Contributing

Changes should preserve the storage-neutral boundary and matching TypeScript/Rust behavior. Do not
add HTTP frameworks, databases, provider SDKs, cryptographic implementations, or product-specific
authorization policy to this repository.

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

From `rust/`:

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo package --locked
```
