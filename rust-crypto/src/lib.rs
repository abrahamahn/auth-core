//! Cryptographic adapters for opaque authentication credentials and protected secrets.

mod csrf;
mod envelope;
mod error;
mod token;

pub use csrf::{
    CSRF_TOKEN_BYTES, CsrfValidationOptions, decrypt_csrf_token, encrypt_csrf_token,
    generate_csrf_token, sign_csrf_token, validate_csrf_token, verify_signed_csrf_token,
};
pub use envelope::{decrypt_secret, encrypt_secret};
pub use error::{CryptoError, CryptoResult};
pub use token::{
    GeneratedOpaqueToken, contextual_device_fingerprint, generate_base64_url_token,
    generate_hex_token, generate_numeric_code, generate_opaque_token, sha256_token_digest,
    stable_device_fingerprint,
};
