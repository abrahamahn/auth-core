//! HS256 JWT and current/previous-secret rotation adapter for Auth Core.

mod error;
mod jwt;
mod rotation;

pub use error::{Expiration, JwtError, JwtErrorCode, JwtPayload};
pub use jwt::{SignOptions, VerifyOptions, decode, sign, verify};
pub use rotation::{
    JwtRotationConfig, JwtRotationHandler, TokenSecretCheck, UsedSecret, check_token_secret,
    sign_with_rotation, verify_with_rotation,
};
