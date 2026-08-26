# auth-crypto

Rust cryptographic adapters for Auth Core.

The crate owns high-entropy opaque-token generation and SHA-256 lookup digests, uniform numeric
one-time codes, the version-1 scrypt/AES-256-GCM secret envelope, and domain-separated device
fingerprints. The envelope is byte-compatible with `@abrahamahn/auth-crypto-node`.

It does not own password hashing, key storage, persisted token lifecycle, recovery semantics,
transport, or authorization policy.
