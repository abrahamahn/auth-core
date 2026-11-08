use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::types::{OAuthError, OAuthErrorCode};

/// RFC 7636 S256 verifier/challenge pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// Generate an OS-random RFC 7636 S256 pair.
///
/// # Errors
/// Returns [`OAuthErrorCode::RandomSource`] if OS randomness fails.
pub fn create_pkce_pair() -> Result<PkcePair, OAuthError> {
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut entropy).map_err(|_| {
        OAuthError::state(
            OAuthErrorCode::RandomSource,
            "operating-system random source failed",
        )
    })?;
    Ok(pkce_pair_from_entropy(&entropy))
}

#[must_use]
pub fn pkce_pair_from_entropy(entropy: &[u8; 32]) -> PkcePair {
    let verifier = URL_SAFE_NO_PAD.encode(entropy);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkcePair {
        verifier,
        challenge,
    }
}

/// Generic protected OAuth state envelope. Application fields live only in `payload`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthStateEnvelope<T> {
    pub nonce: String,
    pub provider: String,
    pub redirect_uri: String,
    pub created_at_ms: u64,
    pub payload: T,
}

/// Generate an OAuth state envelope using OS randomness.
///
/// # Errors
/// Returns a malformed-state or random-source error.
pub fn create_oauth_state<T>(
    provider: impl Into<String>,
    redirect_uri: impl Into<String>,
    payload: T,
    created_at_ms: u64,
) -> Result<OAuthStateEnvelope<T>, OAuthError> {
    let provider = provider.into();
    let redirect_uri = redirect_uri.into();
    if provider.trim().is_empty() || redirect_uri.trim().is_empty() {
        return Err(OAuthError::state(
            OAuthErrorCode::StateMalformed,
            "provider and redirect URI are required",
        ));
    }
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut entropy).map_err(|_| {
        OAuthError::state(
            OAuthErrorCode::RandomSource,
            "operating-system random source failed",
        )
    })?;
    Ok(OAuthStateEnvelope {
        nonce: hex(&entropy),
        provider,
        redirect_uri,
        created_at_ms,
        payload,
    })
}

/// Serialize and protect a state envelope through an application-supplied crypto adapter.
///
/// # Errors
/// Returns a state-protection error for serialization or adapter failure.
pub fn encode_oauth_state<T: Serialize>(
    state: &OAuthStateEnvelope<T>,
    protect: impl FnOnce(&str) -> Result<String, OAuthError>,
) -> Result<String, OAuthError> {
    let json = serde_json::to_string(state).map_err(|_| {
        OAuthError::state(
            OAuthErrorCode::StateProtectionFailed,
            "OAuth state could not be serialized",
        )
    })?;
    protect(&json).map_err(|_| {
        OAuthError::state(
            OAuthErrorCode::StateProtectionFailed,
            "OAuth state protection failed",
        )
    })
}

/// Unprotect, validate, and expire a state envelope through an application crypto adapter.
///
/// # Errors
/// Returns a protection, malformed, or expiry category.
pub fn decode_oauth_state<T: DeserializeOwned>(
    encoded: &str,
    now_ms: u64,
    max_age_ms: u64,
    unprotect: impl FnOnce(&str) -> Result<String, OAuthError>,
) -> Result<OAuthStateEnvelope<T>, OAuthError> {
    if max_age_ms == 0 {
        return Err(OAuthError::state(
            OAuthErrorCode::StateMalformed,
            "max age must be positive",
        ));
    }
    let json = unprotect(encoded).map_err(|_| {
        OAuthError::state(
            OAuthErrorCode::StateProtectionFailed,
            "OAuth state could not be opened",
        )
    })?;
    let state: OAuthStateEnvelope<T> = serde_json::from_str(&json).map_err(|_| {
        OAuthError::state(OAuthErrorCode::StateMalformed, "OAuth state is malformed")
    })?;
    if state.nonce.is_empty() || state.provider.is_empty() || state.redirect_uri.is_empty() {
        return Err(OAuthError::state(
            OAuthErrorCode::StateMalformed,
            "OAuth state has invalid fields",
        ));
    }
    let age = now_ms.checked_sub(state.created_at_ms).ok_or_else(|| {
        OAuthError::state(OAuthErrorCode::StateExpired, "OAuth state has expired")
    })?;
    if age > max_age_ms {
        return Err(OAuthError::state(
            OAuthErrorCode::StateExpired,
            "OAuth state has expired",
        ));
    }
    Ok(state)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
