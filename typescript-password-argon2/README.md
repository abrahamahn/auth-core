# @abrahamahn/auth-password-argon2

Argon2 password-hashing adapter for Auth Core. It owns PHC-string hashing and verification,
parameter-upgrade detection, and dummy-hash verification for unknown-account timing resistance.

The package deliberately does not own password strength policy, credential persistence, account
lockout, HTTP handlers, or application configuration. Those decisions belong to pure Auth Core or
the consuming application.

```ts
import {
  DummyHashPool,
  hashPassword,
  verifyPassword,
} from '@abrahamahn/auth-password-argon2';

const hash = await hashPassword('user supplied password');
const valid = await verifyPassword('user supplied password', hash);

const dummyHashes = new DummyHashPool();
await dummyHashes.initialize();
const loginValid = await dummyHashes.verify(candidatePassword, account?.passwordHash);
```
