# @abrahamahn/auth-core

Pure TypeScript authentication-security primitives for applications that need consistent password and
session behavior without importing an authentication framework or application domain.

## Owns

- configurable password validation and deterministic strength assessment;
- refresh credential classification (`rotate`, retry, reject, or compromise);
- family revocation and reuse-window decisions;
- optional session binding comparison;
- credential-epoch checks;
- session span, idle-window, activity, age, and excess-session eviction calculations;
- account lockout thresholds, unlock timing, and progressive delay.
- one-time credential acceptance, expiry, consumption, and attempt-exhaustion decisions;
- typed immutable authentication audit events with recursive secret-metadata rejection;
- framework-neutral contracts for transaction, audit, notification, OAuth, and WebAuthn adapters.

## Does not own

HTTP implementation, cookies, tokens, hashing algorithms, OAuth and WebAuthn provider SDKs,
persistence implementations, notification delivery, product roles, eligibility, profiles, tenancy,
or resource authorization.

Strength and crack-time estimates are advisory. Applications must supplement the built-in common
password screening with their own current breached-password blocklist before accepting a password.

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```
