//! Transport-neutral OAuth 2.0/OpenID Connect provider protocol and identity adapters.
//!
//! The crate owns provider request construction, response normalization, PKCE, generic state
//! envelopes, and Apple identity-token verification. Applications own HTTP execution, storage,
//! account linking, authorization policy, and user creation.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as EcSignature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use rsa::BigUint;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USERINFO_URL: &str = "https://api.github.com/user";
const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";
const KAKAO_AUTH_URL: &str = "https://kauth.kakao.com/oauth/authorize";
const KAKAO_TOKEN_URL: &str = "https://kauth.kakao.com/oauth/token";
const KAKAO_USERINFO_URL: &str = "https://kapi.kakao.com/v2/user/me";
const APPLE_AUTH_URL: &str = "https://appleid.apple.com/auth/authorize";
const APPLE_TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
const APPLE_KEYS_URL: &str = "https://appleid.apple.com/auth/keys";
const APPLE_ISSUER: &str = "https://appleid.apple.com";
const APPLE_CLIENT_SECRET_MAX_SECONDS: u64 = 180 * 24 * 60 * 60;
const MAX_DATE_MS: u64 = 8_640_000_000_000_000;

/// Supported first-party provider adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Google,
    Github,
    Kakao,
    Apple,
}

impl Display for OAuthProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Google => "google",
            Self::Github => "github",
            Self::Kakao => "kakao",
            Self::Apple => "apple",
        })
    }
}

/// Normalized provider token response. Absolute expirations use Unix milliseconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthTokenSet {
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_at_ms: Option<u64>,
    pub refresh_token_expires_at_ms: Option<u64>,
    pub scope: Option<String>,
}

/// Normalized identity fields required by an application account-linking policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthUserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub email_verified: bool,
    pub picture: Option<String>,
}

/// Machine-readable provider failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthErrorCode {
    InvalidConfig,
    TokenExchangeFailed,
    TokenRefreshFailed,
    UserInfoFailed,
    NoEmail,
    MalformedResponse,
    KeysFetchFailed,
    KeyNotFound,
    InvalidIdToken,
    InvalidAlgorithm,
    InvalidSignature,
    InvalidIssuer,
    InvalidAudience,
    TokenExpired,
    InvalidIssuedAt,
    RandomSource,
    StateMalformed,
    StateExpired,
    StateProtectionFailed,
}

/// OAuth adapter error independent of an application's HTTP hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthError {
    pub provider: Option<OAuthProvider>,
    pub code: OAuthErrorCode,
    pub message: String,
    pub status: Option<u16>,
}

impl OAuthError {
    fn provider(provider: OAuthProvider, code: OAuthErrorCode, message: impl Into<String>) -> Self {
        Self {
            provider: Some(provider),
            code,
            message: message.into(),
            status: None,
        }
    }

    fn state(code: OAuthErrorCode, message: impl Into<String>) -> Self {
        Self {
            provider: None,
            code,
            message: message.into(),
            status: None,
        }
    }

    fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }
}

impl Display for OAuthError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for OAuthError {}

/// HTTP method used by a provider request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// Transport-neutral provider request for execution by reqwest, a worker runtime, or a test fake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthHttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
}

impl OAuthHttpRequest {
    fn get(url: impl Into<String>, bearer: Option<&str>) -> Self {
        let mut headers = BTreeMap::new();
        if let Some(token) = bearer {
            headers.insert("Authorization".to_owned(), format!("Bearer {token}"));
        }
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers,
            body: None,
        }
    }

    fn form_post(url: impl Into<String>, fields: &[(&str, &str)]) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        );
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers,
            body: Some(form_body(fields)),
        }
    }

    fn json_post(url: impl Into<String>, body: &Value) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert("Accept".to_owned(), "application/json".to_owned());
        headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers,
            body: Some(body.to_string()),
        }
    }
}

/// Optional authorization and token-exchange security fields.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorizationOptions {
    pub code_challenge: Option<String>,
    pub login_hint: Option<String>,
    pub prompt: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenExchangeOptions {
    pub code_verifier: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleProvider {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub request_offline_access: bool,
    pub force_consent: bool,
}

impl GoogleProvider {
    /// Construct the provider with identity-only default scopes.
    ///
    /// # Errors
    /// Returns [`OAuthErrorCode::InvalidConfig`] for empty credentials.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        let client_id = required_config(client_id.into(), "client_id", OAuthProvider::Google)?;
        let client_secret =
            required_config(client_secret.into(), "client_secret", OAuthProvider::Google)?;
        Ok(Self {
            client_id,
            client_secret,
            scopes: string_vec(&["openid", "email", "profile"]),
            request_offline_access: true,
            force_consent: false,
        })
    }

    /// Build the browser authorization URL.
    ///
    /// # Errors
    /// Returns an error only if the static provider URL cannot be parsed.
    pub fn authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
        options: &AuthorizationOptions,
    ) -> Result<String, OAuthError> {
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", ""),
            ("state", state),
        ];
        let scopes = self.scopes.join(" ");
        fields[3].1 = &scopes;
        let mut url = authorization_url(GOOGLE_AUTH_URL, &fields, OAuthProvider::Google)?;
        {
            let mut query = url.query_pairs_mut();
            if self.request_offline_access {
                query.append_pair("access_type", "offline");
            }
            if self.force_consent {
                query.append_pair("prompt", "consent");
            }
            append_authorization_options(&mut query, options, "login_hint");
        }
        Ok(url.into())
    }

    #[must_use]
    pub fn exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        options: &TokenExchangeOptions,
    ) -> OAuthHttpRequest {
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(verifier) = &options.code_verifier {
            fields.push(("code_verifier", verifier));
        }
        OAuthHttpRequest::form_post(GOOGLE_TOKEN_URL, &fields)
    }

    #[must_use]
    pub fn user_info_request(&self, access_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::get(GOOGLE_USERINFO_URL, Some(access_token))
    }

    #[must_use]
    pub fn refresh_request(&self, refresh_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::form_post(
            GOOGLE_TOKEN_URL,
            &[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        )
    }

    /// Parse and normalize Google `UserInfo` JSON.
    ///
    /// # Errors
    /// Returns a categorized provider response error.
    pub fn parse_user_info(&self, status: u16, body: &str) -> Result<OAuthUserInfo, OAuthError> {
        let data = response_object(
            status,
            body,
            OAuthProvider::Google,
            OAuthErrorCode::UserInfoFailed,
        )?;
        let email = required_string(
            &data,
            "email",
            OAuthProvider::Google,
            OAuthErrorCode::NoEmail,
        )?;
        Ok(OAuthUserInfo {
            id: required_string(
                &data,
                "sub",
                OAuthProvider::Google,
                OAuthErrorCode::UserInfoFailed,
            )?,
            email,
            name: optional_string(&data, "name"),
            email_verified: boolish(data.get("email_verified")),
            picture: optional_string(&data, "picture"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProvider {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub allow_signup: bool,
}

impl GithubProvider {
    /// # Errors
    /// Returns [`OAuthErrorCode::InvalidConfig`] for empty credentials.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            client_id: required_config(client_id.into(), "client_id", OAuthProvider::Github)?,
            client_secret: required_config(
                client_secret.into(),
                "client_secret",
                OAuthProvider::Github,
            )?,
            scopes: string_vec(&["user:email", "read:user"]),
            allow_signup: true,
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
        let allow_signup = self.allow_signup.to_string();
        let mut url = authorization_url(
            GITHUB_AUTH_URL,
            &[
                ("client_id", &self.client_id),
                ("redirect_uri", redirect_uri),
                ("scope", &scopes),
                ("state", state),
                ("allow_signup", &allow_signup),
            ],
            OAuthProvider::Github,
        )?;
        append_authorization_options(&mut url.query_pairs_mut(), options, "login");
        Ok(url.into())
    }

    #[must_use]
    pub fn exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        options: &TokenExchangeOptions,
    ) -> OAuthHttpRequest {
        let mut body = json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        });
        if let (Some(object), Some(verifier)) = (body.as_object_mut(), &options.code_verifier) {
            object.insert("code_verifier".to_owned(), Value::String(verifier.clone()));
        }
        OAuthHttpRequest::json_post(GITHUB_TOKEN_URL, &body)
    }

    #[must_use]
    pub fn user_info_requests(&self, access_token: &str) -> [OAuthHttpRequest; 2] {
        let mut profile = OAuthHttpRequest::get(GITHUB_USERINFO_URL, Some(access_token));
        let mut emails = OAuthHttpRequest::get(GITHUB_EMAILS_URL, Some(access_token));
        for request in [&mut profile, &mut emails] {
            request.headers.insert(
                "Accept".to_owned(),
                "application/vnd.github+json".to_owned(),
            );
            request
                .headers
                .insert("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned());
        }
        [profile, emails]
    }

    #[must_use]
    pub fn refresh_request(&self, refresh_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::json_post(
            GITHUB_TOKEN_URL,
            &json!({
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }),
        )
    }

    /// Normalize the profile and optional email-list responses.
    ///
    /// # Errors
    /// Returns a categorized provider response error or [`OAuthErrorCode::NoEmail`].
    pub fn parse_user_info(
        &self,
        profile_status: u16,
        profile_body: &str,
        emails_response: Option<(u16, &str)>,
    ) -> Result<OAuthUserInfo, OAuthError> {
        let profile = response_object(
            profile_status,
            profile_body,
            OAuthProvider::Github,
            OAuthErrorCode::UserInfoFailed,
        )?;
        let mut email = optional_string(&profile, "email");
        let mut email_verified = false;
        if let Some((status, body)) = emails_response.filter(|(status, _)| success(*status)) {
            let emails = response_json(
                status,
                body,
                OAuthProvider::Github,
                OAuthErrorCode::UserInfoFailed,
            )?;
            if let Some(items) = emails.as_array() {
                let verified = items
                    .iter()
                    .filter_map(Value::as_object)
                    .find(|entry| {
                        entry.get("primary").and_then(Value::as_bool) == Some(true)
                            && entry.get("verified").and_then(Value::as_bool) == Some(true)
                    })
                    .or_else(|| {
                        items.iter().filter_map(Value::as_object).find(|entry| {
                            entry.get("verified").and_then(Value::as_bool) == Some(true)
                        })
                    });
                if let Some(selected) = verified.and_then(|entry| optional_string(entry, "email")) {
                    email = Some(selected);
                    email_verified = true;
                }
            }
        }
        let email = email.ok_or_else(|| {
            OAuthError::provider(
                OAuthProvider::Github,
                OAuthErrorCode::NoEmail,
                "No email found on GitHub account",
            )
        })?;
        let id = profile
            .get("id")
            .and_then(|value| match value {
                Value::Number(number) => Some(number.to_string()),
                Value::String(value) if !value.is_empty() => Some(value.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                OAuthError::provider(
                    OAuthProvider::Github,
                    OAuthErrorCode::UserInfoFailed,
                    "GitHub response is missing id",
                )
            })?;
        Ok(OAuthUserInfo {
            id,
            email,
            name: optional_string(&profile, "name"),
            email_verified,
            picture: optional_string(&profile, "avatar_url"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KakaoProvider {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
}

impl KakaoProvider {
    /// # Errors
    /// Returns [`OAuthErrorCode::InvalidConfig`] for an empty client ID.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            client_id: required_config(client_id.into(), "client_id", OAuthProvider::Kakao)?,
            client_secret: client_secret.filter(|secret| !secret.trim().is_empty()),
            scopes: string_vec(&["account_email", "profile_nickname", "profile_image"]),
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
        let scopes = self.scopes.join(",");
        let mut url = authorization_url(
            KAKAO_AUTH_URL,
            &[
                ("client_id", &self.client_id),
                ("redirect_uri", redirect_uri),
                ("response_type", "code"),
                ("scope", &scopes),
                ("state", state),
            ],
            OAuthProvider::Kakao,
        )?;
        append_authorization_options(&mut url.query_pairs_mut(), options, "login_hint");
        Ok(url.into())
    }

    #[must_use]
    pub fn exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        options: &TokenExchangeOptions,
    ) -> OAuthHttpRequest {
        self.token_request(
            &[
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
                ("code", code),
            ],
            options.code_verifier.as_deref(),
        )
    }

    #[must_use]
    pub fn refresh_request(&self, refresh_token: &str) -> OAuthHttpRequest {
        self.token_request(
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
            None,
        )
    }

    fn token_request(&self, values: &[(&str, &str)], verifier: Option<&str>) -> OAuthHttpRequest {
        let mut fields = values.to_vec();
        fields.push(("client_id", &self.client_id));
        if let Some(secret) = &self.client_secret {
            fields.push(("client_secret", secret));
        }
        if let Some(verifier) = verifier {
            fields.push(("code_verifier", verifier));
        }
        OAuthHttpRequest::form_post(KAKAO_TOKEN_URL, &fields)
    }

    #[must_use]
    pub fn user_info_request(&self, access_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::get(KAKAO_USERINFO_URL, Some(access_token))
    }

    /// # Errors
    /// Returns a categorized provider response error or [`OAuthErrorCode::NoEmail`].
    pub fn parse_user_info(&self, status: u16, body: &str) -> Result<OAuthUserInfo, OAuthError> {
        let data = response_object(
            status,
            body,
            OAuthProvider::Kakao,
            OAuthErrorCode::UserInfoFailed,
        )?;
        let account = data
            .get("kakao_account")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OAuthError::provider(
                    OAuthProvider::Kakao,
                    OAuthErrorCode::NoEmail,
                    "No email found on Kakao account",
                )
            })?;
        let email = required_string(
            account,
            "email",
            OAuthProvider::Kakao,
            OAuthErrorCode::NoEmail,
        )?;
        let profile = account.get("profile").and_then(Value::as_object);
        let id = data
            .get("id")
            .and_then(|value| match value {
                Value::Number(number) => Some(number.to_string()),
                Value::String(value) if !value.is_empty() => Some(value.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                OAuthError::provider(
                    OAuthProvider::Kakao,
                    OAuthErrorCode::UserInfoFailed,
                    "Kakao response is missing id",
                )
            })?;
        Ok(OAuthUserInfo {
            id,
            email,
            name: profile.and_then(|value| optional_string(value, "nickname")),
            email_verified: boolish(account.get("is_email_verified")),
            picture: profile.and_then(|value| optional_string(value, "profile_image_url")),
        })
    }
}

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
    #[allow(clippy::too_many_lines)]
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
        let signature = RsaSignature::try_from(signature_bytes.as_slice()).map_err(|_| {
            OAuthError::provider(
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIdToken,
                "Apple identity-token signature is malformed",
            )
        })?;
        VerifyingKey::<Sha256>::new(public_key)
            .verify(format!("{header}.{payload}").as_bytes(), &signature)
            .map_err(|_| {
                OAuthError::provider(
                    OAuthProvider::Apple,
                    OAuthErrorCode::InvalidSignature,
                    "Apple identity-token signature is invalid",
                )
            })?;

        let claims = decode_jwt_object(payload)?;
        if optional_string(&claims, "iss").as_deref() != Some(APPLE_ISSUER) {
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
                &claims,
                "sub",
                OAuthProvider::Apple,
                OAuthErrorCode::InvalidIdToken,
            )?,
            email: required_string(
                &claims,
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

/// Parse a token endpoint response for any supported provider.
///
/// # Errors
/// Returns a categorized exchange/refresh failure without copying response bodies into errors.
pub fn parse_token_response(
    provider: OAuthProvider,
    status: u16,
    body: &str,
    now_ms: u64,
    refresh: bool,
) -> Result<OAuthTokenSet, OAuthError> {
    let code = if refresh {
        OAuthErrorCode::TokenRefreshFailed
    } else {
        OAuthErrorCode::TokenExchangeFailed
    };
    let data = response_object(status, body, provider, code)?;
    if let Some(error) = optional_string(&data, "error") {
        return Err(OAuthError::provider(
            provider,
            code,
            optional_string(&data, "error_description").unwrap_or(error),
        ));
    }
    if now_ms > MAX_DATE_MS {
        return Err(OAuthError::provider(
            provider,
            OAuthErrorCode::InvalidConfig,
            "OAuth clock returned an invalid timestamp",
        ));
    }
    let expires_at_ms = optional_expiration_ms(&data, "expires_in", now_ms, provider, code)?;
    let refresh_token_expires_at_ms =
        optional_expiration_ms(&data, "refresh_token_expires_in", now_ms, provider, code)?;
    Ok(OAuthTokenSet {
        access_token: required_string(&data, "access_token", provider, code)?,
        token_type: optional_string(&data, "token_type").unwrap_or_else(|| "Bearer".to_owned()),
        refresh_token: optional_string(&data, "refresh_token"),
        id_token: optional_string(&data, "id_token"),
        expires_at_ms,
        refresh_token_expires_at_ms,
        scope: optional_string(&data, "scope"),
    })
}

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

fn required_config(
    value: String,
    field: &str,
    provider: OAuthProvider,
) -> Result<String, OAuthError> {
    if value.trim().is_empty() {
        Err(OAuthError::provider(
            provider,
            OAuthErrorCode::InvalidConfig,
            format!("{field} is required"),
        ))
    } else {
        Ok(value)
    }
}

fn string_vec(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn authorization_url(
    base: &str,
    fields: &[(&str, &str)],
    provider: OAuthProvider,
) -> Result<Url, OAuthError> {
    let mut url = Url::parse(base).map_err(|_| {
        OAuthError::provider(
            provider,
            OAuthErrorCode::InvalidConfig,
            "provider authorization URL is invalid",
        )
    })?;
    url.query_pairs_mut().extend_pairs(fields.iter().copied());
    Ok(url)
}

fn append_authorization_options(
    query: &mut url::form_urlencoded::Serializer<'_, url::UrlQuery<'_>>,
    options: &AuthorizationOptions,
    login_field: &str,
) {
    if let Some(prompt) = &options.prompt {
        query.append_pair("prompt", prompt);
    }
    if let Some(login_hint) = &options.login_hint {
        query.append_pair(login_field, login_hint);
    }
    if let Some(challenge) = &options.code_challenge {
        query
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
    }
}

fn form_body(fields: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish()
}

fn success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn response_json(
    status: u16,
    body: &str,
    provider: OAuthProvider,
    code: OAuthErrorCode,
) -> Result<Value, OAuthError> {
    if !success(status) {
        return Err(OAuthError::provider(
            provider,
            code,
            format!("provider request failed with HTTP {status}"),
        )
        .with_status(status));
    }
    serde_json::from_str(body)
        .map_err(|_| OAuthError::provider(provider, code, "provider returned invalid JSON"))
}

fn response_object(
    status: u16,
    body: &str,
    provider: OAuthProvider,
    code: OAuthErrorCode,
) -> Result<Map<String, Value>, OAuthError> {
    response_json(status, body, provider, code)?
        .as_object()
        .cloned()
        .ok_or_else(|| OAuthError::provider(provider, code, "provider returned an invalid object"))
}

fn optional_string(data: &Map<String, Value>, field: &str) -> Option<String> {
    data.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_string(
    data: &Map<String, Value>,
    field: &str,
    provider: OAuthProvider,
    code: OAuthErrorCode,
) -> Result<String, OAuthError> {
    optional_string(data, field).ok_or_else(|| {
        OAuthError::provider(
            provider,
            code,
            format!("provider response is missing {field}"),
        )
    })
}

fn optional_expiration_ms(
    data: &Map<String, Value>,
    field: &str,
    now_ms: u64,
    provider: OAuthProvider,
    code: OAuthErrorCode,
) -> Result<Option<u64>, OAuthError> {
    let Some(value) = data.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let seconds = value.as_u64().ok_or_else(|| {
        OAuthError::provider(
            provider,
            code,
            format!("provider response has invalid {field}"),
        )
    })?;
    let expires_at_ms = seconds
        .checked_mul(1_000)
        .and_then(|duration_ms| now_ms.checked_add(duration_ms))
        .filter(|expires_at_ms| *expires_at_ms <= MAX_DATE_MS)
        .ok_or_else(|| {
            OAuthError::provider(
                provider,
                code,
                format!("provider response {field} exceeds the supported date range"),
            )
        })?;
    Ok(Some(expires_at_ms))
}

fn boolish(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true))) || value.and_then(Value::as_str) == Some("true")
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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
