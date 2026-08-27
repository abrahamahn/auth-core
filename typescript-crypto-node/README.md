# @abrahamahn/auth-crypto-node

Node.js cryptographic adapters for Auth Core.

The package owns high-entropy opaque-token generation and SHA-256 lookup digests, uniform numeric
one-time codes, the version-1 scrypt/AES-256-GCM secret envelope, and domain-separated device
fingerprints. It also owns HMAC signing, AES-GCM cookie protection, and constant-time double-submit
validation for CSRF tokens. It does not own password hashing, key storage, persisted token lifecycle,
cookie policy, HTTP middleware, recovery semantics, or authorization policy.
