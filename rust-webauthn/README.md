# auth-webauthn

Rust WebAuthn relying-party adapter for Auth Core, backed by `webauthn-rs`. It starts and verifies
passkey registration/authentication ceremonies and exposes serializable browser options,
server-side ceremony state, and passkeys.

`InMemoryWebauthnCeremonyStore` provides checked, consume-before-verify storage for tests and
single-process deployments. Distributed deployments must provide an atomic shared store with the
same single-use behavior.

Applications must store ceremony state server-side, consume it once, enforce global credential-ID
uniqueness, associate passkeys with their own principals, and persist passkey counter/backup-state
updates after successful authentication. This crate does not own HTTP routes, users, sessions, or a
database schema.

The upstream state-serialization feature is intentionally enabled so distributed servers can place
ceremony state in a database or shared cache. Never send serialized registration or authentication
state to a browser or store it in a client-side cookie: replaying it can bypass WebAuthn guarantees.

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo package
```
