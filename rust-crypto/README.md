# auth-crypto

Rust cryptographic adapters for Auth Core.

The crate owns high-entropy opaque-token generation and SHA-256 lookup digests, uniform numeric
one-time codes, the version-1 scrypt/AES-256-GCM secret envelope, and domain-separated device
fingerprints. It also owns HMAC signing, AES-GCM cookie protection, and constant-time double-submit
validation for CSRF tokens. Both encrypted formats are byte-compatible with
`@abrahamahn/auth-crypto-node`.

It does not own password hashing, key storage, persisted token lifecycle, recovery semantics,
cookie policy, transport middleware, or authorization policy.
