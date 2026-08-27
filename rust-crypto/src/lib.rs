//! Cryptographic adapters for opaque authentication credentials and protected secrets.

use std::error::Error;
use std::fmt::{Display, Formatter};

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, AesGcm, Nonce, Tag};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use scrypt::{Params as ScryptParams, scrypt};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const ENCRYPTION_KEY_BYTES: usize = 32;
const IV_BYTES: usize = 12;
const SALT_BYTES: usize = 16;
const AUTH_TAG_BYTES: usize = 16;
const MAX_NUMERIC_CODE_DIGITS: u32 = 14;
const CSRF_IV_BYTES: usize = 16;
const CSRF_ENCRYPTION_CONTEXT: &[u8] = b"csrf-encryption-key";

pub const CSRF_TOKEN_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;
type CsrfCipher = AesGcm<aes_gcm::aes::Aes256, U16>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidByteCount,
    InvalidDigits,
    EmptyEncryptionKey,
    EmptySecret,
    InvalidEnvelope,
    InvalidEnvelopeField,
    RandomSource,
    KeyDerivation,
    Encryption,
    Decryption,
}

impl Display for CryptoError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidByteCount => "token byte count must be positive",
            Self::InvalidDigits => "numeric-code digits must be from 1 through 14",
            Self::EmptyEncryptionKey => "encryption key must not be empty",
            Self::EmptySecret => "secret must not be empty",
            Self::InvalidEnvelope => "invalid encrypted secret format",
            Self::InvalidEnvelopeField => "invalid encrypted secret field",
            Self::RandomSource => "operating-system random source failed",
            Self::KeyDerivation => "secret-envelope key derivation failed",
            Self::Encryption => "secret-envelope encryption failed",
            Self::Decryption => "secret-envelope authentication or decryption failed",
        })
    }
}

impl Error for CryptoError {}

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedOpaqueToken {
    pub plain: String,
    pub digest: String,
}

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

#[must_use]
pub fn sha256_token_digest(token: &str) -> String {
    hex_encode(&Sha256::digest(token.as_bytes()))
}

/// Generates an OS-random hexadecimal token.
///
/// # Errors
///
/// Returns [`CryptoError`] when `bytes` is zero or the OS random source fails.
pub fn generate_hex_token(bytes: usize) -> CryptoResult<String> {
    Ok(hex_encode(&random_bytes(bytes)?))
}

/// Generates an OS-random unpadded base64url token.
///
/// # Errors
///
/// Returns [`CryptoError`] when `bytes` is zero or the OS random source fails.
pub fn generate_base64_url_token(bytes: usize) -> CryptoResult<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes(bytes)?))
}

/// Generates a hexadecimal opaque token together with its SHA-256 lookup digest.
///
/// # Errors
///
/// Returns [`CryptoError`] when `bytes` is zero or the OS random source fails.
pub fn generate_opaque_token(bytes: usize) -> CryptoResult<GeneratedOpaqueToken> {
    let plain = generate_hex_token(bytes)?;
    let digest = sha256_token_digest(&plain);
    Ok(GeneratedOpaqueToken { plain, digest })
}

/// Generates a uniformly distributed, zero-padded numeric one-time code.
///
/// # Errors
///
/// Returns [`CryptoError`] for an invalid digit count or failed OS random source.
pub fn generate_numeric_code(digits: u32) -> CryptoResult<String> {
    if digits == 0 || digits > MAX_NUMERIC_CODE_DIGITS {
        return Err(CryptoError::InvalidDigits);
    }
    let upper = 10_u64
        .checked_pow(digits)
        .ok_or(CryptoError::InvalidDigits)?;
    let unbiased_upper = u64::MAX - (u64::MAX % upper);
    loop {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).map_err(|_| CryptoError::RandomSource)?;
        let candidate = u64::from_le_bytes(entropy);
        if candidate < unbiased_upper {
            return Ok(format!(
                "{:0width$}",
                candidate % upper,
                width = digits as usize
            ));
        }
    }
}

/// Encrypts a secret into the version-1 scrypt/AES-256-GCM envelope.
///
/// # Errors
///
/// Returns [`CryptoError`] for an empty key, failed random source, key derivation, or encryption.
pub fn encrypt_secret(plaintext: &str, encryption_key: &str) -> CryptoResult<String> {
    require_encryption_key(encryption_key)?;
    let salt: [u8; SALT_BYTES] = random_bytes(SALT_BYTES)?
        .try_into()
        .map_err(|_| CryptoError::RandomSource)?;
    let iv: [u8; IV_BYTES] = random_bytes(IV_BYTES)?
        .try_into()
        .map_err(|_| CryptoError::RandomSource)?;
    encrypt_secret_with_entropy(plaintext, encryption_key, &salt, &iv)
}

/// Decrypts and authenticates a version-1 scrypt/AES-256-GCM envelope.
///
/// # Errors
///
/// Returns [`CryptoError`] for malformed fields, an empty key, key derivation failure, failed
/// authentication, or non-UTF-8 plaintext.
pub fn decrypt_secret(envelope: &str, encryption_key: &str) -> CryptoResult<String> {
    require_encryption_key(encryption_key)?;
    let parts = envelope.split(':').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let salt = decode_fixed::<SALT_BYTES>(parts[0])?;
    let iv = decode_fixed::<IV_BYTES>(parts[1])?;
    let tag = decode_fixed::<AUTH_TAG_BYTES>(parts[2])?;
    let mut encrypted = STANDARD
        .decode(parts[3])
        .map_err(|_| CryptoError::InvalidEnvelopeField)?;
    let key = derive_key(encryption_key, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::KeyDerivation)?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&iv),
            b"",
            &mut encrypted,
            Tag::from_slice(&tag),
        )
        .map_err(|_| CryptoError::Decryption)?;
    String::from_utf8(encrypted).map_err(|_| CryptoError::Decryption)
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

#[must_use]
pub fn contextual_device_fingerprint(identity: &str, user_agent: &str) -> String {
    sha256_token_digest(&format!("{identity}:{user_agent}"))
}

#[must_use]
pub fn stable_device_fingerprint(device_id: &str) -> String {
    sha256_token_digest(&format!("device:{device_id}"))
}

fn encrypt_secret_with_entropy(
    plaintext: &str,
    encryption_key: &str,
    salt: &[u8; SALT_BYTES],
    iv: &[u8; IV_BYTES],
) -> CryptoResult<String> {
    let key = derive_key(encryption_key, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::KeyDerivation)?;
    let mut encrypted = plaintext.as_bytes().to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(iv), b"", &mut encrypted)
        .map_err(|_| CryptoError::Encryption)?;
    Ok([
        STANDARD.encode(salt),
        STANDARD.encode(iv),
        STANDARD.encode(tag),
        STANDARD.encode(encrypted),
    ]
    .join(":"))
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

fn derive_key(encryption_key: &str, salt: &[u8]) -> CryptoResult<[u8; ENCRYPTION_KEY_BYTES]> {
    let params = ScryptParams::new(14, 8, 1, ENCRYPTION_KEY_BYTES)
        .map_err(|_| CryptoError::KeyDerivation)?;
    let mut key = [0_u8; ENCRYPTION_KEY_BYTES];
    scrypt(encryption_key.as_bytes(), salt, &params, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

fn random_bytes(bytes: usize) -> CryptoResult<Vec<u8>> {
    if bytes == 0 {
        return Err(CryptoError::InvalidByteCount);
    }
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value).map_err(|_| CryptoError::RandomSource)?;
    Ok(value)
}

fn require_encryption_key(encryption_key: &str) -> CryptoResult<()> {
    if encryption_key.is_empty() {
        Err(CryptoError::EmptyEncryptionKey)
    } else {
        Ok(())
    }
}

fn require_secret(secret: &str) -> CryptoResult<()> {
    if secret.is_empty() {
        Err(CryptoError::EmptySecret)
    } else {
        Ok(())
    }
}

fn decode_fixed<const LENGTH: usize>(encoded: &str) -> CryptoResult<[u8; LENGTH]> {
    STANDARD
        .decode(encoded)
        .map_err(|_| CryptoError::InvalidEnvelopeField)?
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelopeField)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        if let Some(high) = char::from_digit(u32::from(byte >> 4), 16) {
            encoded.push(high);
        }
        if let Some(low) = char::from_digit(u32::from(byte & 0x0f), 16) {
            encoded.push(low);
        }
    }
    encoded
}
