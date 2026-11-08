use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{AesGcm, Nonce, Tag};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{AUTH_TAG_BYTES, CryptoError, CryptoResult, random_bytes};
use crate::token::generate_base64_url_token;

const CSRF_IV_BYTES: usize = 16;
const CSRF_ENCRYPTION_CONTEXT: &[u8] = b"csrf-encryption-key";

pub const CSRF_TOKEN_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;
type CsrfCipher = AesGcm<aes_gcm::aes::Aes256, U16>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CsrfValidationOptions {
    pub encrypted: bool,
    pub signed: bool,
}

impl Default for CsrfValidationOptions {
    fn default() -> Self {
        Self {
            encrypted: false,
            signed: true,
        }
    }
}

/// Generates an OS-random unpadded base64url token for double-submit CSRF protection.
///
/// # Errors
///
/// Returns [`CryptoError`] if the OS random source fails.
pub fn generate_csrf_token() -> CryptoResult<String> {
    generate_base64_url_token(CSRF_TOKEN_BYTES)
}

/// Signs a CSRF token with HMAC-SHA-256 using the `token.signature` wire format.
///
/// # Errors
///
/// Returns [`CryptoError`] when the secret is empty.
pub fn sign_csrf_token(token: &str, secret: &str) -> CryptoResult<String> {
    require_secret(secret)?;
    let signature = csrf_hmac(token.as_bytes(), secret)?;
    Ok(format!("{token}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// Authenticates and unwraps a signed CSRF token.
///
/// Malformed or unauthenticated input returns `Ok(None)`.
///
/// # Errors
///
/// Returns [`CryptoError`] when the secret is empty.
pub fn verify_signed_csrf_token(signed_token: &str, secret: &str) -> CryptoResult<Option<String>> {
    require_secret(secret)?;
    let Some((token, signature)) = signed_token.rsplit_once('.') else {
        return Ok(None);
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return Ok(None);
    };
    let mut mac = create_csrf_mac(secret)?;
    mac.update(token.as_bytes());
    if mac.verify_slice(&signature).is_err() {
        return Ok(None);
    }
    Ok(Some(token.to_owned()))
}

/// Protects a CSRF cookie value with the AES-256-GCM `iv.ciphertext.tag` wire format.
///
/// # Errors
///
/// Returns [`CryptoError`] for an empty secret, failed random source, or encryption failure.
pub fn encrypt_csrf_token(token: &str, secret: &str) -> CryptoResult<String> {
    require_secret(secret)?;
    let iv: [u8; CSRF_IV_BYTES] = random_bytes(CSRF_IV_BYTES)?
        .try_into()
        .map_err(|_| CryptoError::RandomSource)?;
    encrypt_csrf_token_with_iv(token, secret, &iv)
}

/// Authenticates and decrypts a CSRF cookie value.
///
/// Malformed or unauthenticated input returns `Ok(None)`.
///
/// # Errors
///
/// Returns [`CryptoError`] when the secret is empty or key derivation fails.
pub fn decrypt_csrf_token(envelope: &str, secret: &str) -> CryptoResult<Option<String>> {
    require_secret(secret)?;
    let parts = envelope.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Ok(None);
    }
    let Ok(iv) = URL_SAFE_NO_PAD.decode(parts[0]) else {
        return Ok(None);
    };
    let Ok(mut encrypted) = URL_SAFE_NO_PAD.decode(parts[1]) else {
        return Ok(None);
    };
    let Ok(tag) = URL_SAFE_NO_PAD.decode(parts[2]) else {
        return Ok(None);
    };
    let (Ok(iv), Ok(tag)) = (
        <[u8; CSRF_IV_BYTES]>::try_from(iv),
        <[u8; AUTH_TAG_BYTES]>::try_from(tag),
    ) else {
        return Ok(None);
    };
    let cipher = CsrfCipher::new_from_slice(&derive_csrf_encryption_key(secret)?)
        .map_err(|_| CryptoError::KeyDerivation)?;
    if cipher
        .decrypt_in_place_detached(
            Nonce::<U16>::from_slice(&iv),
            b"",
            &mut encrypted,
            Tag::from_slice(&tag),
        )
        .is_err()
    {
        return Ok(None);
    }
    Ok(String::from_utf8(encrypted).ok())
}

/// Validates the cookie/request pair used by double-submit CSRF protection.
///
/// # Errors
///
/// Returns [`CryptoError`] when the secret is empty or cryptographic setup fails.
pub fn validate_csrf_token(
    cookie_token: Option<&str>,
    request_token: Option<&str>,
    secret: &str,
    options: CsrfValidationOptions,
) -> CryptoResult<bool> {
    require_secret(secret)?;
    let (Some(cookie_token), Some(request_token)) = (cookie_token, request_token) else {
        return Ok(false);
    };
    if cookie_token.is_empty() || request_token.is_empty() {
        return Ok(false);
    }

    let protected_token = if options.encrypted {
        let Some(decrypted) = decrypt_csrf_token(cookie_token, secret)? else {
            return Ok(false);
        };
        decrypted
    } else {
        cookie_token.to_owned()
    };
    let unwrapped = if options.signed {
        let Some(token) = verify_signed_csrf_token(&protected_token, secret)? else {
            return Ok(false);
        };
        token
    } else {
        protected_token
    };
    Ok(bool::from(
        unwrapped.as_bytes().ct_eq(request_token.as_bytes()),
    ))
}

fn encrypt_csrf_token_with_iv(
    token: &str,
    secret: &str,
    iv: &[u8; CSRF_IV_BYTES],
) -> CryptoResult<String> {
    let cipher = CsrfCipher::new_from_slice(&derive_csrf_encryption_key(secret)?)
        .map_err(|_| CryptoError::KeyDerivation)?;
    let mut encrypted = token.as_bytes().to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::<U16>::from_slice(iv), b"", &mut encrypted)
        .map_err(|_| CryptoError::Encryption)?;
    Ok([
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(encrypted),
        URL_SAFE_NO_PAD.encode(tag),
    ]
    .join("."))
}

fn create_csrf_mac(secret: &str) -> CryptoResult<HmacSha256> {
    <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()).map_err(|_| CryptoError::KeyDerivation)
}

fn csrf_hmac(input: &[u8], secret: &str) -> CryptoResult<[u8; 32]> {
    let mut mac = create_csrf_mac(secret)?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().into())
}

fn derive_csrf_encryption_key(secret: &str) -> CryptoResult<[u8; 32]> {
    csrf_hmac(CSRF_ENCRYPTION_CONTEXT, secret)
}

fn require_secret(secret: &str) -> CryptoResult<()> {
    if secret.is_empty() {
        Err(CryptoError::EmptySecret)
    } else {
        Ok(())
    }
}
