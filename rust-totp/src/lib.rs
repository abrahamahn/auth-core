//! Storage-neutral TOTP and recovery-code primitives.

use std::error::Error;
use std::fmt::Write;
use std::fmt::{Display, Formatter};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    const fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotpConfig {
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period_seconds: u64,
}

pub const DEFAULT_TOTP_CONFIG: TotpConfig = TotpConfig {
    algorithm: TotpAlgorithm::Sha1,
    digits: 6,
    period_seconds: 30,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TotpError {
    InvalidSecret,
    InvalidDigits,
    InvalidPeriod,
    InvalidWindow,
    InvalidIssuer,
    InvalidLabel,
    EmptyRecoveryEntropy,
    InvalidRecoveryGroupSize,
}

impl Display for TotpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSecret => "TOTP secret must be valid base32",
            Self::InvalidDigits => "TOTP digits must be from 6 through 8",
            Self::InvalidPeriod => "TOTP period_seconds must be positive",
            Self::InvalidWindow => "TOTP verification window is too large",
            Self::InvalidIssuer => "TOTP issuer must not be empty",
            Self::InvalidLabel => "TOTP label must not be empty",
            Self::EmptyRecoveryEntropy => "recovery-code entropy must not be empty",
            Self::InvalidRecoveryGroupSize => "recovery-code group size must be positive",
        })
    }
}

impl Error for TotpError {}

pub type TotpResult<T> = Result<T, TotpError>;

fn validate_config(config: TotpConfig) -> TotpResult<()> {
    if !(6..=8).contains(&config.digits) {
        return Err(TotpError::InvalidDigits);
    }
    if config.period_seconds == 0 {
        return Err(TotpError::InvalidPeriod);
    }
    Ok(())
}

fn decode_secret(secret_base32: &str) -> TotpResult<Vec<u8>> {
    let normalized = secret_base32
        .trim()
        .trim_end_matches('=')
        .to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| TotpError::InvalidSecret)
}

fn dynamic_truncate(digest: &[u8], digits: u32) -> TotpResult<String> {
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.checked_pow(digits).ok_or(TotpError::InvalidDigits)?;
    let code = binary % modulus;
    Ok(format!("{code:0width$}", width = digits as usize))
}

fn code_for_counter(secret: &[u8], counter: u64, config: TotpConfig) -> TotpResult<String> {
    let counter_bytes = counter.to_be_bytes();
    let digest = match config.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac =
                Hmac::<Sha1>::new_from_slice(secret).map_err(|_| TotpError::InvalidSecret)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).map_err(|_| TotpError::InvalidSecret)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(secret).map_err(|_| TotpError::InvalidSecret)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };
    dynamic_truncate(&digest, config.digits)
}

/// Generates the TOTP code at an explicit Unix timestamp in milliseconds.
///
/// # Errors
///
/// Returns [`TotpError`] when the configuration or base32 secret is invalid.
pub fn generate_totp_code(
    secret_base32: &str,
    timestamp_ms: u64,
    config: TotpConfig,
) -> TotpResult<String> {
    validate_config(config)?;
    let secret = decode_secret(secret_base32)?;
    let counter = timestamp_ms / 1_000 / config.period_seconds;
    code_for_counter(&secret, counter, config)
}

/// Verifies a TOTP code at an explicit Unix timestamp and bounded step window.
///
/// # Errors
///
/// Returns [`TotpError`] when the configuration, base32 secret, or window is invalid.
pub fn verify_totp_code(
    secret_base32: &str,
    code: &str,
    timestamp_ms: u64,
    window: u32,
    config: TotpConfig,
) -> TotpResult<bool> {
    validate_config(config)?;
    if window > i32::MAX as u32 {
        return Err(TotpError::InvalidWindow);
    }
    if code.len() != config.digits as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(false);
    }
    let secret = decode_secret(secret_base32)?;
    let counter = timestamp_ms / 1_000 / config.period_seconds;
    let signed_window = i64::from(window);
    for offset in -signed_window..=signed_window {
        if let Some(candidate_counter) = counter.checked_add_signed(offset) {
            let candidate = code_for_counter(&secret, candidate_counter, config)?;
            if bool::from(candidate.as_bytes().ct_eq(code.as_bytes())) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Builds a canonical `otpauth://` enrollment URI from a caller-owned secret.
///
/// # Errors
///
/// Returns [`TotpError`] when the configuration, secret, issuer, or label is invalid.
pub fn create_totp_uri(
    secret_base32: &str,
    issuer: &str,
    label: &str,
    config: TotpConfig,
) -> TotpResult<String> {
    validate_config(config)?;
    decode_secret(secret_base32)?;
    if issuer.trim().is_empty() {
        return Err(TotpError::InvalidIssuer);
    }
    if label.trim().is_empty() {
        return Err(TotpError::InvalidLabel);
    }
    let issuer_encoded = utf8_percent_encode(issuer, NON_ALPHANUMERIC);
    let label_encoded = utf8_percent_encode(label, NON_ALPHANUMERIC);
    Ok(format!(
        "otpauth://totp/{issuer_encoded}:{label_encoded}?secret={secret_base32}&issuer={issuer_encoded}&algorithm={}&digits={}&period={}",
        config.algorithm.label(),
        config.digits,
        config.period_seconds,
    ))
}

/// Formats caller-provided secure entropy as a grouped hexadecimal recovery code.
///
/// # Errors
///
/// Returns [`TotpError`] when entropy is empty or the group size is zero.
pub fn format_recovery_code(entropy: &[u8], group_size: usize) -> TotpResult<String> {
    if entropy.is_empty() {
        return Err(TotpError::EmptyRecoveryEntropy);
    }
    if group_size == 0 {
        return Err(TotpError::InvalidRecoveryGroupSize);
    }
    let mut encoded = String::with_capacity(entropy.len() * 2);
    for byte in entropy {
        if write!(&mut encoded, "{byte:02X}").is_err() {
            return Err(TotpError::EmptyRecoveryEntropy);
        }
    }
    let separator_count = encoded.len().saturating_sub(1) / group_size;
    let mut grouped = String::with_capacity(encoded.len() + separator_count);
    for (index, character) in encoded.chars().enumerate() {
        if index > 0 && index % group_size == 0 {
            grouped.push('-');
        }
        grouped.push(character);
    }
    Ok(grouped)
}
