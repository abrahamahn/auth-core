# auth-password-argon2

Rust Argon2 password-hashing adapter for Auth Core. It owns PHC-string hashing and verification,
parameter-upgrade detection, and dummy-hash verification for unknown-account timing resistance.

Password strength policy, credential persistence, account lockout, HTTP, and application
configuration remain outside this crate.
