use std::fmt;

use serde_json::{Map, Value};

/// Object payload returned after verification.
pub type JwtPayload = Map<String, Value>;

/// Stable machine-readable JWT failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtErrorCode {
    InvalidToken,
    InvalidSignature,
    TokenExpired,
    MalformedToken,
}

/// JWT adapter failure independent of any HTTP or application error hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwtError {
    pub code: JwtErrorCode,
    pub message: String,
}

impl JwtError {
    pub(crate) fn new(message: impl Into<String>, code: JwtErrorCode) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for JwtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JwtError {}

/// Relative JWT lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expiration {
    Seconds(u64),
    Duration(String),
}

impl From<u64> for Expiration {
    fn from(seconds: u64) -> Self {
        Self::Seconds(seconds)
    }
}

impl From<&str> for Expiration {
    fn from(duration: &str) -> Self {
        Self::Duration(duration.to_owned())
    }
}

impl From<String> for Expiration {
    fn from(duration: String) -> Self {
        Self::Duration(duration)
    }
}

impl Expiration {
    pub(crate) fn seconds(&self) -> Result<u64, JwtError> {
        match self {
            Self::Seconds(seconds) => Ok(*seconds),
            Self::Duration(duration) => {
                let Some(unit) = duration.chars().last() else {
                    return Err(invalid_expiration(duration));
                };
                let digits = &duration[..duration.len().saturating_sub(unit.len_utf8())];
                if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid_expiration(duration));
                }
                let value = digits
                    .parse::<u64>()
                    .map_err(|_| invalid_expiration(duration))?;
                let multiplier = match unit {
                    's' => 1,
                    'm' => 60,
                    'h' => 3_600,
                    'd' => 86_400,
                    _ => return Err(invalid_expiration(duration)),
                };
                value
                    .checked_mul(multiplier)
                    .ok_or_else(|| invalid_expiration(duration))
            }
        }
    }
}

fn invalid_expiration(duration: &str) -> JwtError {
    JwtError::new(
        format!("Invalid expiration format: {duration}"),
        JwtErrorCode::InvalidToken,
    )
}
