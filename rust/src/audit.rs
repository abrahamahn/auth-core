use std::collections::BTreeMap;

use crate::{AuthError, AuthResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAuditEventType {
    TokenReuseDetected,
    TokenFamilyRevoked,
    SessionRevoked,
    AccountLocked,
    AccountUnlocked,
    SuspiciousLogin,
    NewDeviceLogin,
    DeviceTrusted,
    DeviceRevoked,
    PasswordChanged,
    EmailChanged,
    MagicLinkRequested,
    MagicLinkVerified,
    MagicLinkFailed,
    EmailOtpRequested,
    EmailOtpVerified,
    EmailOtpFailed,
    OauthLoginSuccess,
    OauthLoginFailure,
    OauthAccountCreated,
    OauthLinkSuccess,
    OauthLinkFailure,
    OauthUnlinkSuccess,
    OauthUnlinkFailure,
    WebauthnRegistered,
    WebauthnAuthenticationSuccess,
    WebauthnAuthenticationFailure,
    WebauthnCredentialRemoved,
    MfaChallenge,
    MfaSuccess,
    MfaFailure,
}

impl AuthAuditEventType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenReuseDetected => "token_reuse_detected",
            Self::TokenFamilyRevoked => "token_family_revoked",
            Self::SessionRevoked => "session_revoked",
            Self::AccountLocked => "account_locked",
            Self::AccountUnlocked => "account_unlocked",
            Self::SuspiciousLogin => "suspicious_login",
            Self::NewDeviceLogin => "new_device_login",
            Self::DeviceTrusted => "device_trusted",
            Self::DeviceRevoked => "device_revoked",
            Self::PasswordChanged => "password_changed",
            Self::EmailChanged => "email_changed",
            Self::MagicLinkRequested => "magic_link_requested",
            Self::MagicLinkVerified => "magic_link_verified",
            Self::MagicLinkFailed => "magic_link_failed",
            Self::EmailOtpRequested => "email_otp_requested",
            Self::EmailOtpVerified => "email_otp_verified",
            Self::EmailOtpFailed => "email_otp_failed",
            Self::OauthLoginSuccess => "oauth_login_success",
            Self::OauthLoginFailure => "oauth_login_failure",
            Self::OauthAccountCreated => "oauth_account_created",
            Self::OauthLinkSuccess => "oauth_link_success",
            Self::OauthLinkFailure => "oauth_link_failure",
            Self::OauthUnlinkSuccess => "oauth_unlink_success",
            Self::OauthUnlinkFailure => "oauth_unlink_failure",
            Self::WebauthnRegistered => "webauthn_registered",
            Self::WebauthnAuthenticationSuccess => "webauthn_authentication_success",
            Self::WebauthnAuthenticationFailure => "webauthn_authentication_failure",
            Self::WebauthnCredentialRemoved => "webauthn_credential_removed",
            Self::MfaChallenge => "mfa_challenge",
            Self::MfaSuccess => "mfa_success",
            Self::MfaFailure => "mfa_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAuditSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAuditOutcome {
    Success,
    Failure,
    Denied,
    Informational,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAuditFactor {
    Password,
    MagicLink,
    EmailOtp,
    Totp,
    Webauthn,
    Oauth,
    RefreshToken,
    Session,
    RecoveryCode,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthAuditMetadataValue {
    Null,
    Boolean(bool),
    Number(f64),
    String(String),
    List(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

pub type AuthAuditMetadata = BTreeMap<String, AuthAuditMetadataValue>;

#[derive(Clone, Debug, PartialEq)]
pub struct AuthAuditEvent {
    pub event_type: AuthAuditEventType,
    pub severity: AuthAuditSeverity,
    pub outcome: AuthAuditOutcome,
    pub occurred_at_ms: i64,
    pub subject_id: Option<String>,
    pub actor_id: Option<String>,
    pub email: Option<String>,
    pub factor: Option<AuthAuditFactor>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: AuthAuditMetadata,
}

impl AuthAuditEvent {
    /// Builds an audit event after recursively checking metadata for secrets and invalid numbers.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidValue`] when metadata includes a secret-bearing key or a
    /// non-finite number.
    pub fn new(
        event_type: AuthAuditEventType,
        severity: AuthAuditSeverity,
        outcome: AuthAuditOutcome,
        occurred_at_ms: i64,
        metadata: AuthAuditMetadata,
    ) -> AuthResult<Self> {
        validate_auth_audit_metadata(&metadata)?;
        Ok(Self {
            event_type,
            severity,
            outcome,
            occurred_at_ms,
            subject_id: None,
            actor_id: None,
            email: None,
            factor: None,
            ip_address: None,
            user_agent: None,
            metadata,
        })
    }
}

#[must_use]
pub fn is_sensitive_auth_audit_metadata_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "password"
            | "passwordhash"
            | "passworddigest"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "csrftoken"
            | "magictoken"
            | "secret"
            | "clientsecret"
            | "code"
            | "recoverycode"
            | "authorization"
            | "cookie"
            | "setcookie"
            | "apikey"
            | "privatekey"
    )
}

fn validate_metadata_value(value: &AuthAuditMetadataValue) -> AuthResult<()> {
    match value {
        AuthAuditMetadataValue::Number(number) if !number.is_finite() => Err(
            AuthError::InvalidValue("audit metadata numbers must be finite"),
        ),
        AuthAuditMetadataValue::List(values) => {
            for value in values {
                validate_metadata_value(value)?;
            }
            Ok(())
        }
        AuthAuditMetadataValue::Object(metadata) => validate_auth_audit_metadata(metadata),
        AuthAuditMetadataValue::Null
        | AuthAuditMetadataValue::Boolean(_)
        | AuthAuditMetadataValue::Number(_)
        | AuthAuditMetadataValue::String(_) => Ok(()),
    }
}

/// Recursively validates audit metadata without logging or returning secret values.
///
/// # Errors
///
/// Returns [`AuthError::InvalidValue`] for secret-bearing keys and non-finite numbers.
pub fn validate_auth_audit_metadata(metadata: &AuthAuditMetadata) -> AuthResult<()> {
    for (key, value) in metadata {
        if is_sensitive_auth_audit_metadata_key(key) {
            return Err(AuthError::InvalidValue(
                "secret-bearing audit metadata key is not permitted",
            ));
        }
        validate_metadata_value(value)?;
    }
    Ok(())
}
