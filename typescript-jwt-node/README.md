# @abrahamahn/auth-jwt-node

Synchronous Node.js HS256 JWT adapter for Auth Core. It owns signing, verification, untrusted
decoding, expiration validation, constant-time signature comparison, and current/previous-secret
rotation.

The package does not own access-token payload schemas, role assignments, issuer or audience policy,
key storage, HTTP authorization parsing, cookie policy, or application error mapping.

```ts
import { createJwtRotationHandler } from '@abrahamahn/auth-jwt-node';

const jwt = createJwtRotationHandler({
  secret: process.env.JWT_SECRET!,
  previousSecret: process.env.JWT_SECRET_PREVIOUS,
});

const token = jwt.sign({ subject: 'user-123' }, { expiresIn: '15m' });
const payload = jwt.verify(token, { clockToleranceSeconds: 30 });
```
