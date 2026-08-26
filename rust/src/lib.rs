//! Deterministic, storage-neutral authentication security primitives.
//!
//! Applications adapt persisted facts into this crate's pure password, session, refresh-token,
//! and lockout decisions. Transport, cryptography, persistence, and product authorization stay
//! outside the core.

mod authorization;
mod challenge;
mod error;
mod lockout;
mod password;
mod session;

pub use authorization::{AuthorizationDecision, RbacError, RbacPolicy, RoleDefinition};
pub use challenge::ExpiringReplayGuard;
pub use error::{AuthError, AuthResult};
pub use lockout::{
    AccountLockoutDecision, AccountLockoutFacts, AccountLockoutPolicy, evaluate_account_lockout,
    is_lockout_threshold_reached, progressive_delay_ms,
};
pub use password::{
    BasicPasswordValidationResult, COMMON_PASSWORDS, DEFAULT_PASSWORD_CONFIG, KEYBOARD_PATTERNS,
    PasswordConfig, PasswordFeedback, PasswordPenalties, PasswordScore, PasswordValidationResult,
    StrengthResult, calculate_entropy, calculate_score, contains_user_input, estimate_crack_time,
    estimate_password_strength, generate_feedback, get_charset_size, get_strength_label,
    has_keyboard_pattern, has_repeated_chars, has_repeated_pattern, has_sequential_chars,
    is_common_password, validate_password, validate_password_basic,
};
pub use session::{
    RefreshCredentialDecision, RefreshCredentialFacts, SessionBindingDecision,
    SessionLifetimePolicy, classify_refresh_credential, credential_epoch_matches,
    derive_session_span_ms, evaluate_session_binding, is_active_refresh_credential,
    is_refresh_retry_eligible, is_session_active, is_session_idle, is_session_revoked,
    select_sessions_for_eviction, session_age_ms, session_idle_remaining_ms,
    session_idle_window_ms, session_span_ms,
};
