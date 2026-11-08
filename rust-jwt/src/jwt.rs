use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use serde_json::{Number, Value, json};
use sha2::Sha256;

use crate::error::{Expiration, JwtError, JwtErrorCode, JwtPayload};

type HmacSha256 = Hmac<Sha256>;

/// JWT signing options.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignOptions {
    pub expires_in: Option<Expiration>,
    /// Deterministic override. Omit in production to use the system clock.
    pub issued_at_seconds: Option<u64>,
}

/// JWT verification options.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifyOptions {
    pub clock_tolerance_seconds: u64,
    /// Deterministic override. Omit in production to use the system clock.
    pub current_time_seconds: Option<u64>,
}

fn unix_time_seconds() -> Result<u64, JwtError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            JwtError::new(
                "System clock is before Unix epoch",
                JwtErrorCode::InvalidToken,
            )
        })
}

fn require_secret(secret: &[u8]) -> Result<(), JwtError> {
    if secret.is_empty() {
        return Err(JwtError::new(
            "JWT secret is required",
            JwtErrorCode::InvalidToken,
        ));
    }
    Ok(())
}

fn encode_json(value: &Value) -> Result<String, JwtError> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| JwtError::new("Malformed token payload", JwtErrorCode::MalformedToken))
}

fn signature(input: &str, secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    require_secret(secret)?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| JwtError::new("JWT secret is required", JwtErrorCode::InvalidToken))?;
    mac.update(input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn decode_json(encoded: &str, message: &'static str) -> Result<Value, JwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JwtError::new(message, JwtErrorCode::MalformedToken))?;
    serde_json::from_slice(&bytes).map_err(|_| JwtError::new(message, JwtErrorCode::MalformedToken))
}

fn parse_header(encoded: &str) -> Result<(), JwtError> {
    let header = decode_json(encoded, "Invalid header")?;
    let Some(header) = header.as_object() else {
        return Err(JwtError::new(
            "Invalid header",
            JwtErrorCode::MalformedToken,
        ));
    };
    if header.get("alg") != Some(&Value::String("HS256".to_owned()))
        || header.get("typ") != Some(&Value::String("JWT".to_owned()))
    {
        return Err(JwtError::new(
            "Algorithm not supported",
            JwtErrorCode::InvalidToken,
        ));
    }
    Ok(())
}

fn parse_payload(encoded: &str) -> Result<JwtPayload, JwtError> {
    let payload = decode_json(encoded, "Malformed token payload")?;
    payload
        .as_object()
        .cloned()
        .ok_or_else(|| JwtError::new("Malformed token payload", JwtErrorCode::MalformedToken))
}

fn validate_expiration(payload: &JwtPayload, options: VerifyOptions) -> Result<(), JwtError> {
    let Some(expiration) = payload.get("exp") else {
        return Ok(());
    };
    let Some(expiration) = expiration.as_u64() else {
        return Err(JwtError::new(
            "Malformed token payload",
            JwtErrorCode::MalformedToken,
        ));
    };
    let current_time = match options.current_time_seconds {
        Some(current_time) => current_time,
        None => unix_time_seconds()?,
    };
    let accepted_until = expiration.saturating_add(options.clock_tolerance_seconds);
    if current_time >= accepted_until {
        return Err(JwtError::new(
            "Token has expired",
            JwtErrorCode::TokenExpired,
        ));
    }
    Ok(())
}

/// Sign an object payload using HS256.
///
/// # Errors
///
/// Returns an error for an empty secret, invalid duration, overflowing timestamp, or payload that
/// cannot be serialized.
pub fn sign(
    payload: &JwtPayload,
    secret: &[u8],
    options: &SignOptions,
) -> Result<String, JwtError> {
    require_secret(secret)?;
    let issued_at = match options.issued_at_seconds {
        Some(issued_at) => issued_at,
        None => unix_time_seconds()?,
    };

    let mut token_payload = payload.clone();
    token_payload.insert("iat".to_owned(), Value::Number(Number::from(issued_at)));
    if let Some(expires_in) = &options.expires_in {
        let expiration = issued_at
            .checked_add(expires_in.seconds()?)
            .ok_or_else(|| {
                JwtError::new(
                    "JWT expiration exceeds supported range",
                    JwtErrorCode::InvalidToken,
                )
            })?;
        token_payload.insert("exp".to_owned(), Value::Number(Number::from(expiration)));
    }
    if token_payload
        .get("exp")
        .is_some_and(|expiration| expiration.as_u64().is_none())
    {
        return Err(JwtError::new(
            "Malformed token payload",
            JwtErrorCode::MalformedToken,
        ));
    }

    let encoded_header = encode_json(&json!({ "alg": "HS256", "typ": "JWT" }))?;
    let encoded_payload = encode_json(&Value::Object(token_payload))?;
    let input = format!("{encoded_header}.{encoded_payload}");
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature(&input, secret)?);
    Ok(format!("{input}.{encoded_signature}"))
}

/// Verify an HS256 JWT and return its object payload.
///
/// # Errors
///
/// Returns a categorized error for malformed structure, unsupported headers, invalid signatures,
/// invalid claims, or expiration.
pub fn verify(token: &str, secret: &[u8], options: VerifyOptions) -> Result<JwtPayload, JwtError> {
    require_secret(secret)?;
    let mut parts = token.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::new(
            "Invalid token format",
            JwtErrorCode::MalformedToken,
        ));
    };
    if encoded_header.is_empty() || encoded_payload.is_empty() || encoded_signature.is_empty() {
        return Err(JwtError::new(
            "Invalid token format",
            JwtErrorCode::MalformedToken,
        ));
    }

    parse_header(encoded_header)?;
    let provided_signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| JwtError::new("Invalid signature", JwtErrorCode::InvalidSignature))?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| JwtError::new("JWT secret is required", JwtErrorCode::InvalidToken))?;
    mac.update(format!("{encoded_header}.{encoded_payload}").as_bytes());
    if mac.verify_slice(&provided_signature).is_err() {
        return Err(JwtError::new(
            "Invalid signature",
            JwtErrorCode::InvalidSignature,
        ));
    }

    let payload = parse_payload(encoded_payload)?;
    validate_expiration(&payload, options)?;
    Ok(payload)
}

/// Decode a JWT payload without verification. Never authorize from this result.
#[must_use]
pub fn decode(token: &str) -> Option<JwtPayload> {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if payload.is_empty() {
        return None;
    }
    parse_payload(payload).ok()
}
