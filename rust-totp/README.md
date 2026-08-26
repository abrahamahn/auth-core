# auth-totp

Storage-neutral Rust TOTP enrollment, verification, and recovery-code primitives for Auth Core.

The crate owns RFC 6238 code generation/verification, `otpauth://` enrollment URIs, and
recovery-code formatting. Applications own entropy generation, persistence, secret encryption,
one-time recovery-code claiming, rate limits, transport, and product wording.
