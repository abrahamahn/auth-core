# auth-jwt

Rust HS256 JWT adapter for Auth Core. It owns signing, verification, untrusted decoding,
expiration validation, constant-time HMAC verification, and current/previous-secret rotation.

Application claim schemas, authorization roles, issuer and audience policy, key storage, HTTP
parsing, and application error mapping remain outside this crate.
