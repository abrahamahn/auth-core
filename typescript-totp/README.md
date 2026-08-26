# @abrahamahn/auth-totp

Storage-neutral TOTP enrollment, verification, and recovery-code primitives for Auth Core.

The package owns RFC 6238 code generation/verification, `otpauth://` enrollment URIs, secret
generation, and recovery-code formatting. Applications own persistence, encryption at rest,
one-time recovery-code claiming, rate limits, HTTP handlers, and product wording.
