# @abrahamahn/auth-webauthn-node

Node.js WebAuthn relying-party adapter for Auth Core. It validates relying-party configuration,
normalizes untrusted browser responses, generates registration/authentication options, verifies
attestations and assertions with `@simplewebauthn/server`, and returns persistence-neutral
credential facts.

The package also defines a ceremony-store contract. `InMemoryWebAuthnCeremonyStore` is intended for
tests and single-process deployments only. Production systems with multiple server instances must
provide an atomic shared implementation and persist each ceremony's challenge server-side.
Injected ceremony clocks must return non-negative safe-integer Unix milliseconds; expiry overflow
is rejected before state is stored.

It does not own users, credential database rows, HTTP routes, sessions, application eligibility, or
passkey display names.

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```
