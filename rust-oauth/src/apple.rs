use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as EcSignature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use rsa::BigUint;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::types::{
    AuthorizationOptions, OAuthError, OAuthErrorCode, OAuthHttpRequest, OAuthProvider,
    OAuthUserInfo, TokenExchangeOptions, authorization_url, boolish, optional_string,
    required_config, required_string, response_object, string_vec,
};

const APPLE_AUTH_URL: &str = "https://appleid.apple.com/auth/authorize";
const APPLE_TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
const APPLE_KEYS_URL: &str = "https://appleid.apple.com/auth/keys";
const APPLE_ISSUER: &str = "https://appleid.apple.com";
const APPLE_CLIENT_SECRET_MAX_SECONDS: u64 = 180 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleProvider {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    pub private_key_pem: String,
    pub scopes: Vec<String>,
    pub clock_tolerance_seconds: u64,
}

impl AppleProvider {
    /// # Errors
    /// Returns [`OAuthErrorCode::InvalidConfig`] for empty credentials.
    pub fn new(
        client_id: impl Into<String>,
        team_id: impl Into<String>,
        key_id: impl Into<String>,
        private_key_pem: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            client_id: required_config(client_id.into(), "client_id", OAuthProvider::Apple)?,
            team_id: required_config(team_id.into(), "team_id", OAuthProvider::Apple)?,
            key_id: required_config(key_id.into(), "key_id", OAuthProvider::Apple)?,
            private_key_pem: required_config(
                private_key_pem.into(),
                "private_key_pem",
                OAuthProvider::Apple,
            )?,
            scopes: string_vec(&["email", "name"]),
            clock_tolerance_seconds: 300,
        })
    }

    /// # Errors
    /// Returns an error only if the static provider URL cannot be parsed.
    pub fn authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
        options: &AuthorizationOptions,
    ) -> Result<String, OAuthError> {
        let scopes = self.scopes.join(" ");
        let mut url = authorization_url(
            APPLE_AUTH_URL,
            &[
                ("client_id", &self.client_id),
                ("redirect_uri", redirect_uri),
                ("response_type", "code"),
                ("response_mode", "form_post"),
                ("scope", &scopes),
                ("state", state),
            ],
            OAuthProvider::Apple,
        )?;
        if let Some(challenge) = &options.code_challenge {
            url.query_pairs_mut()
                .append_pair("code_challenge", challenge)
                .append_pair("code_challenge_method", "S256");
        }
        Ok(url.into())
    }

    /// Build Apple's signed client assertion.
    ///
    /// # Errors
    /// Returns an invalid-configuration error for a malformed key or excessive lifetime.
    pub fn client_secret(
        &self,
        issued_at_seconds: u64,
        lifetime_seconds: u64,
    ) -> Result<String, OAuthError> {
        if lifetime_seconds == 0 || lifetime_seconds > APPLE_CLIENT_SECRET_MAX_SECONDS {
            return Err(OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidConfig,
                "Apple client secret lifetime must be from 1 second through 180 days",
            ));
        }
        let expires_at = issued_at_seconds
            .checked_add(lifetime_seconds)
            .ok_or_else(|| {
                OAuthError::provider(
                    OAuthProvider::Apple,
                    OAuthErrorCode::InvalidConfig,
                    "Apple client secret expiration overflowed",
                )
            })?;
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({ "alg": "ES256", "kid": self.key_id, "typ": "JWT" }))
                .map_err(|_| {
                    OAuthError::provider(
                        OAuthProvider::Apple,
                        OAuthErrorCode::InvalidConfig,
                        "Apple client secret header could not be encoded",
                    )
                })?,
        );
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": self.team_id,
                "iat": issued_at_seconds,
                "exp": expires_at,
                "aud": APPLE_ISSUER,
                "sub": self.client_id,
            }))
            .map_err(|_| {
                OAuthError::provider(
                    OAuthProvider::Apple,
                    OAuthErrorCode::InvalidConfig,
                    "Apple client secret claims could not be encoded",
                )
            })?,
        );
        let input = format!("{header}.{payload}");
        let key = SigningKey::from_pkcs8_pem(&self.private_key_pem).map_err(|_| {
            OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidConfig,
                "Apple private key is invalid",
            )
        })?;
        let signature: EcSignature = key.sign(input.as_bytes());
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    /// # Errors
    /// Returns an error if the client assertion cannot be generated.
    pub fn exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        options: &TokenExchangeOptions,
        now_seconds: u64,
    ) -> Result<OAuthHttpRequest, OAuthError> {
        let secret = self.client_secret(now_seconds, APPLE_CLIENT_SECRET_MAX_SECONDS)?;
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(verifier) = &options.code_verifier {
            fields.push(("code_verifier", verifier));
        }
        Ok(OAuthHttpRequest::form_post(APPLE_TOKEN_URL, &fields))
    }

    /// # Errors
    /// Returns an error if the client assertion cannot be generated.
    pub fn refresh_request(
        &self,
        refresh_token: &str,
        now_seconds: u64,
    ) -> Result<OAuthHttpRequest, OAuthError> {
        let secret = self.client_secret(now_seconds, APPLE_CLIENT_SECRET_MAX_SECONDS)?;
        Ok(OAuthHttpRequest::form_post(
            APPLE_TOKEN_URL,
            &[
                ("client_id", &self.client_id),
                ("client_secret", &secret),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        ))
    }

    #[must_use]
    pub fn keys_request(&self) -> OAuthHttpRequest {
        OAuthHttpRequest::get(APPLE_KEYS_URL, None)
    }

    /// Verify an Apple RS256 identity token and normalize its identity claims.
    ///
    /// # Errors
    /// Returns a stable signature, claim, key, expiry, or email failure category.
    pub fn verify_user_info(
        &self,
        id_token: &str,
        jwks_status: u16,
        jwks_body: &str,
        now_seconds: u64,
    ) -> Result<OAuthUserInfo, OAuthError> {
        let mut parts = id_token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIdToken,
                "Apple returned a malformed identity token",
            ));
        };
        verify_apple_signature(header, payload, signature, jwks_status, jwks_body)?;
        let claims = decode_jwt_object(payload)?;
        self.validate_apple_claims(&claims, now_seconds)
    }

    fn validate_apple_claims(
        &self,
        claims: &Map<String, Value>,
        now_seconds: u64,
    ) -> Result<OAuthUserInfo, OAuthError> {
        if optional_string(claims, "iss").as_deref() != Some(APPLE_ISSUER) {
            return Err(OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIssuer,
                "Apple identity-token issuer is invalid",
            ));
        }
        let audience_valid = claims.get("aud").is_some_and(|audience| match audience {
            Value::String(value) => value == &self.client_id,
            Value::Array(values) => values
                .iter()
                .any(|value| value.as_str() == Some(&self.client_id)),
            _ => false,
        });
        if !audience_valid {
            return Err(OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidAudience,
                "Apple identity-token audience is invalid",
            ));
        }
        let expiration = claims.get("exp").and_then(Value::as_u64).ok_or_else(|| {
            OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIdToken,
                "Apple identity-token expiration is missing",
            )
        })?;
        if now_seconds >= expiration.saturating_add(self.clock_tolerance_seconds) {
            return Err(OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::TokenExpired,
                "Apple identity token has expired",
            ));
        }
        let issued_at = claims.get("iat").and_then(Value::as_u64).ok_or_else(|| {
            OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIdToken,
                "Apple identity-token issued-at is missing",
            )
        })?;
        if issued_at > now_seconds.saturating_add(self.clock_tolerance_seconds) {
            return Err(OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIssuedAt,
                "Apple identity token was issued in the future",
            ));
        }
        Ok(OAuthUserInfo {
            id: required_string(
                claims,
                "sub",
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIdToken,
            )?,
            email: required_string(
                claims,
                "email",
                OAuthProvider::Apple,
                OAuthErrorCode::NoEmail,
            )?,
            name: None,
            email_verified: boolish(claims.get("email_verified")),
            picture: None,
        })
    }
}

fn verify_apple_signature(
    header: &str,
    payload: &str,
    signature: &str,
    jwks_status: u16,
    jwks_body: &str,
) -> Result<(), OAuthError> {
    let header_value = decode_jwt_object(header)?;
    if optional_string(&header_value, "alg").as_deref() != Some("RS256") {
        return Err(OAuthError::provider(
            OAuthProvider::Apple,
            OAuthErrorCode::InvalidAlgorithm,
            "Apple identity token must use RS256",
        ));
    }
    let kid = required_string(
        &header_value,
        "kid",
        OAuthProvider::Apple,
        OAuthErrorCode::InvalidIdToken,
    )?;
    let keys = response_object(
        jwks_status,
        jwks_body,
        OAuthProvider::Apple,
        OAuthErrorCode::KeysFetchFailed,
    )?;
    let key = keys
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().filter_map(Value::as_object).find(|candidate| {
                optional_string(candidate, "kid").as_deref() == Some(kid.as_str())
            })
        })
        .ok_or_else(|| {
            OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::KeyNotFound,
                "Apple public key was not found",
            )
        })?;
    if optional_string(key, "kty").as_deref() != Some("RSA")
        || optional_string(key, "alg").is_some_and(|algorithm| algorithm != "RS256")
    {
        return Err(OAuthError::provider(
            OAuthProvider::Apple,
            OAuthErrorCode::InvalidAlgorithm,
            "Apple public key is not an RS256 key",
        ));
    }
    let modulus = decode_jwk_component(key, "n")?;
    let exponent = decode_jwk_component(key, "e")?;
    let public_key = RsaPublicKey::new(
        BigUint::from_bytes_be(&modulus),
        BigUint::from_bytes_be(&exponent),
    )
    .map_err(|_| {
        OAuthError::provider(
            OAuthProvider::Apple,
            OAuthErrorCode::InvalidIdToken,
            "Apple public key is invalid",
        )
    })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature).map_err(|_| {
        OAuthError::provider(
            OAuthProvider::Apple,
            OAuthErrorCode::InvalidIdToken,
            "Apple identity-token signature is malformed",
        )
    })?;
    let rsa_signature = RsaSignature::try_from(signature_bytes.as_slice()).map_err(|_| {
        OAuthError::provider(
            OAuthProvider::Apple,
            OAuthErrorCode::InvalidIdToken,
            "Apple identity-token signature is malformed",
        )
    })?;
    VerifyingKey::<Sha256>::new(public_key)
        .verify(format!("{header}.{payload}").as_bytes(), &rsa_signature)
        .map_err(|_| {
            OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidSignature,
                "Apple identity-token signature is invalid",
            )
        })
}

fn decode_jwt_object(encoded: &str) -> Result<Map<String, Value>, OAuthError> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        OAuthError::provider(
            OAuthProvider::Apple,
            OAuthErrorCode::InvalidIdToken,
            "Apple identity token is malformed",
        )
    })?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| {
            OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIdToken,
                "Apple identity token is malformed",
            )
        })
}

fn decode_jwk_component(key: &Map<String, Value>, field: &str) -> Result<Vec<u8>, OAuthError> {
    let encoded = required_string(
        key,
        field,
        OAuthProvider::Apple,
        OAuthErrorCode::InvalidIdToken,
    )?;
    URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        OAuthError::provider(
            OAuthProvider::Apple,
            OAuthErrorCode::InvalidIdToken,
            "Apple public key is malformed",
        )
    })
}
