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

## Does not own

HTTP, cookies, tokens, hashing algorithms, OAuth, WebAuthn transport, persistence, notifications,
product roles, eligibility, profiles, tenancy, or resource authorization.

Strength and crack-time estimates are advisory. Applications must supplement the built-in common
password screening with their own current breached-password blocklist before accepting a password.

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```
