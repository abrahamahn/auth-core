# @abrahamahn/auth-oauth-node

Node.js OAuth 2.0/OpenID Connect provider adapters for Auth Core. It owns normalized token and
identity contracts, authorization/code/refresh requests for Google, GitHub, Kakao, and Apple,
PKCE generation, generic protected-state lifecycle, and verified Apple identity tokens.

The package does not own HTTP routes, cookies, token storage, account linking, user creation,
roles, eligibility, or product policy. HTTP execution is injectable for deterministic tests.

```ts
import { createGoogleProvider, createPkcePair } from '@abrahamahn/auth-oauth-node';

const google = createGoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
});
const pkce = createPkcePair();
const url = google.getAuthorizationUrl('protected-state', 'https://app.example/callback', {
  codeChallenge: pkce.challenge,
});

const tokens = await google.exchangeCode('authorization-code', 'https://app.example/callback', {
  codeVerifier: pkce.verifier,
});
const identity = await google.getUserInfo(tokens);
```

Provider endpoints and request behavior follow the providers' official server-side OAuth
documentation. Consumers remain responsible for protecting state, secrets, and stored tokens.
