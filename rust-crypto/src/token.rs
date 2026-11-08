use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::error::{CryptoError, CryptoResult, hex_encode, random_bytes};

const MAX_NUMERIC_CODE_DIGITS: u32 = 14;

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

#[must_use]
pub fn contextual_device_fingerprint(identity: &str, user_agent: &str) -> String {
    sha256_token_digest(&format!("{identity}:{user_agent}"))
}

#[must_use]
pub fn stable_device_fingerprint(device_id: &str) -> String {
    sha256_token_digest(&format!("device:{device_id}"))
}
