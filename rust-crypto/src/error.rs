use std::error::Error;
use std::fmt::{Display, Formatter};

pub(crate) const AUTH_TAG_BYTES: usize = 16;

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

pub(crate) fn random_bytes(bytes: usize) -> CryptoResult<Vec<u8>> {
    if bytes == 0 {
        return Err(CryptoError::InvalidByteCount);
    }
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value).map_err(|_| CryptoError::RandomSource)?;
    Ok(value)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
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
