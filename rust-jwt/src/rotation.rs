use crate::error::{JwtError, JwtErrorCode, JwtPayload};
use crate::jwt::{SignOptions, VerifyOptions, sign, verify};

/// Borrowed key-rotation configuration.
#[derive(Clone, Copy, Debug)]
pub struct JwtRotationConfig<'a> {
    pub secret: &'a [u8],
    pub previous_secret: Option<&'a [u8]>,
}

/// Which configured key verified a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsedSecret {
    Current,
    Previous,
    None,
}

/// Non-throwing rotation diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenSecretCheck {
    pub is_valid: bool,
    pub used_secret: UsedSecret,
    pub error: Option<JwtError>,
}

/// Sign only with the current secret.
///
/// # Errors
///
/// Returns the same errors as [`sign`].
pub fn sign_with_rotation(
    payload: &JwtPayload,
    config: JwtRotationConfig<'_>,
    options: &SignOptions,
) -> Result<String, JwtError> {
    sign(payload, config.secret, options)
}

/// Verify with the current secret, falling back only after a signature mismatch.
///
/// # Errors
///
/// Returns the current-secret error when neither configured secret verifies the token.
pub fn verify_with_rotation(
    token: &str,
    config: JwtRotationConfig<'_>,
    options: VerifyOptions,
) -> Result<JwtPayload, JwtError> {
    let current_error = match verify(token, config.secret, options) {
        Ok(payload) => return Ok(payload),
        Err(error) => error,
    };
    if current_error.code == JwtErrorCode::InvalidSignature
        && let Some(previous_secret) = config.previous_secret.filter(|secret| !secret.is_empty())
    {
        return verify(token, previous_secret, options).map_err(|_| current_error);
    }
    Err(current_error)
}

/// Report which configured secret verifies a token.
#[must_use]
pub fn check_token_secret(
    token: &str,
    config: JwtRotationConfig<'_>,
    options: VerifyOptions,
) -> TokenSecretCheck {
    let Err(current_error) = verify(token, config.secret, options) else {
        return TokenSecretCheck {
            is_valid: true,
            used_secret: UsedSecret::Current,
            error: None,
        };
    };
    if current_error.code == JwtErrorCode::InvalidSignature
        && let Some(previous_secret) = config.previous_secret.filter(|secret| !secret.is_empty())
        && verify(token, previous_secret, options).is_ok()
    {
        return TokenSecretCheck {
            is_valid: true,
            used_secret: UsedSecret::Previous,
            error: None,
        };
    }
    TokenSecretCheck {
        is_valid: false,
        used_secret: UsedSecret::None,
        error: Some(current_error),
    }
}

/// Owned facade for a stable current/previous-secret configuration.
#[derive(Clone, Debug)]
pub struct JwtRotationHandler {
    secret: Vec<u8>,
    previous_secret: Option<Vec<u8>>,
}

impl JwtRotationHandler {
    #[must_use]
    pub fn new(secret: impl Into<Vec<u8>>, previous_secret: Option<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            previous_secret,
        }
    }

    fn config(&self) -> JwtRotationConfig<'_> {
        JwtRotationConfig {
            secret: &self.secret,
            previous_secret: self.previous_secret.as_deref(),
        }
    }

    /// Sign with the current secret.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`sign`].
    pub fn sign(&self, payload: &JwtPayload, options: &SignOptions) -> Result<String, JwtError> {
        sign_with_rotation(payload, self.config(), options)
    }

    /// Verify with the configured rotation strategy.
    ///
    /// # Errors
    ///
    /// Returns the current-secret error when verification fails.
    pub fn verify(&self, token: &str, options: VerifyOptions) -> Result<JwtPayload, JwtError> {
        verify_with_rotation(token, self.config(), options)
    }

    #[must_use]
    pub fn check_secret(&self, token: &str, options: VerifyOptions) -> TokenSecretCheck {
        check_token_secret(token, self.config(), options)
    }

    #[must_use]
    pub fn is_rotating(&self) -> bool {
        self.previous_secret
            .as_deref()
            .is_some_and(|secret| !secret.is_empty())
    }

    #[must_use]
    pub fn has_secret(&self) -> bool {
        !self.secret.is_empty()
    }
}
