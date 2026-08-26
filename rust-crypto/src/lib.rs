//! Cryptographic adapters for opaque authentication credentials and protected secrets.

use std::error::Error;
use std::fmt::{Display, Formatter};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use scrypt::{Params as ScryptParams, scrypt};
use sha2::{Digest, Sha256};

const ENCRYPTION_KEY_BYTES: usize = 32;
const IV_BYTES: usize = 12;
const SALT_BYTES: usize = 16;
const AUTH_TAG_BYTES: usize = 16;
const MAX_NUMERIC_CODE_DIGITS: u32 = 14;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidByteCount,
    InvalidDigits,
    EmptyEncryptionKey,
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
