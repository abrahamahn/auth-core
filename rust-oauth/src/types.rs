use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

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
    pub(crate) fn provider(
        provider: OAuthProvider,
        code: OAuthErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            provider: Some(provider),
            code,
            message: message.into(),
            status: None,
        }
    }

    pub(crate) fn state(code: OAuthErrorCode, message: impl Into<String>) -> Self {
        Self {
            provider: None,
            code,
            message: message.into(),
            status: None,
        }
    }

    pub(crate) fn with_status(mut self, status: u16) -> Self {
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
    pub(crate) fn get(url: impl Into<String>, bearer: Option<&str>) -> Self {
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

    pub(crate) fn form_post(url: impl Into<String>, fields: &[(&str, &str)]) -> Self {
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

    pub(crate) fn json_post(url: impl Into<String>, body: &Value) -> Self {
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

pub(crate) fn required_config(
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

pub(crate) fn string_vec(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

pub(crate) fn authorization_url(
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

pub(crate) fn append_authorization_options(
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

pub(crate) fn success(status: u16) -> bool {
    (200..300).contains(&status)
}

pub(crate) fn response_json(
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

pub(crate) fn response_object(
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

pub(crate) fn optional_string(data: &Map<String, Value>, field: &str) -> Option<String> {
    data.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn required_string(
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

pub(crate) fn required_id(
    data: &Map<String, Value>,
    provider: OAuthProvider,
    missing_message: &'static str,
) -> Result<String, OAuthError> {
    data.get("id")
        .and_then(|value| match value {
            Value::Number(number) => Some(number.to_string()),
            Value::String(value) if !value.is_empty() => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            OAuthError::provider(provider, OAuthErrorCode::UserInfoFailed, missing_message)
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

pub(crate) fn boolish(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true))) || value.and_then(Value::as_str) == Some("true")
}
