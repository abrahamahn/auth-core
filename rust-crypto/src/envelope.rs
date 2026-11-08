use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use scrypt::{Params as ScryptParams, scrypt};

use crate::error::{AUTH_TAG_BYTES, CryptoError, CryptoResult, random_bytes};

const ENCRYPTION_KEY_BYTES: usize = 32;
const IV_BYTES: usize = 12;
const SALT_BYTES: usize = 16;

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
