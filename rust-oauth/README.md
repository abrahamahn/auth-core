# auth-oauth

Transport-neutral Rust OAuth 2.0/OpenID Connect provider protocol for Auth Core. It owns normalized
token and identity contracts, Google/GitHub/Kakao/Apple request construction and response parsing,
PKCE, generic protected-state lifecycle, Apple ES256 client assertions, and Apple RS256 identity
verification.

The consuming application executes `OAuthHttpRequest` with its chosen HTTP runtime. HTTP route
mounting, storage, account linking, user creation, roles, eligibility, and product policy remain
outside this crate.
