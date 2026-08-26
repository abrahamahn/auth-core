use crate::{AuthError, AuthResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshCredentialFacts {
    pub now_ms: i64,
    pub expires_at_ms: i64,
    pub rotated_at_ms: Option<i64>,
    pub family_revoked_at_ms: Option<i64>,
    pub grace_period_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshCredentialDecision {
    Rotate,
    RetryCurrent,
    RejectExpired,
    RevokeFamilyRevoked,
    RevokeCredentialReuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionBindingDecision {
    Unbound,
    NotChecked,
    Match,
    Mismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLifetimePolicy {
    pub default_span_ms: u64,
    pub remembered_span_ms: u64,
    pub max_idle_ms: u64,
}

#[must_use]
pub fn classify_refresh_credential(facts: RefreshCredentialFacts) -> RefreshCredentialDecision {
    if facts.family_revoked_at_ms.is_some() {
        return RefreshCredentialDecision::RevokeFamilyRevoked;
    }
    if facts.expires_at_ms <= facts.now_ms {
        return RefreshCredentialDecision::RejectExpired;
    }
    let Some(rotated_at_ms) = facts.rotated_at_ms else {
        return RefreshCredentialDecision::Rotate;
    };
    let elapsed = i128::from(facts.now_ms) - i128::from(rotated_at_ms);
    if elapsed < i128::from(facts.grace_period_ms) {
        RefreshCredentialDecision::RetryCurrent
    } else {
        RefreshCredentialDecision::RevokeCredentialReuse
    }
}

#[must_use]
pub const fn credential_epoch_matches(observed_epoch: u64, current_epoch: u64) -> bool {
    observed_epoch == current_epoch
}

#[must_use]
pub fn is_refresh_retry_eligible(
    facts: RefreshCredentialFacts,
    observed_credential_epoch: u64,
    current_credential_epoch: u64,
) -> bool {
    credential_epoch_matches(observed_credential_epoch, current_credential_epoch)
        && classify_refresh_credential(facts) == RefreshCredentialDecision::RetryCurrent
}

#[must_use]
pub fn is_active_refresh_credential(facts: RefreshCredentialFacts) -> bool {
    classify_refresh_credential(facts) == RefreshCredentialDecision::Rotate
}

#[must_use]
pub fn evaluate_session_binding(
    expected_binding: Option<&str>,
    presented_binding: Option<&str>,
) -> SessionBindingDecision {
    match (expected_binding, presented_binding) {
        (None | Some(""), _) => SessionBindingDecision::Unbound,
        (Some(_), None) => SessionBindingDecision::NotChecked,
        (Some(expected), Some(presented)) if expected == presented => SessionBindingDecision::Match,
        (Some(_), Some(_)) => SessionBindingDecision::Mismatch,
    }
}

#[must_use]
pub const fn session_span_ms(remembered: Option<bool>, policy: SessionLifetimePolicy) -> u64 {
    if matches!(remembered, Some(true)) {
        policy.remembered_span_ms
    } else {
        policy.default_span_ms
    }
}

/// Derives the issued session span from creation and expiration timestamps.
///
/// # Errors
///
/// Returns [`AuthError::ArithmeticOverflow`] when the difference exceeds `i64`.
pub fn derive_session_span_ms(created_at_ms: i64, expires_at_ms: i64) -> AuthResult<i64> {
    expires_at_ms
        .checked_sub(created_at_ms)
        .ok_or(AuthError::ArithmeticOverflow("session span overflowed i64"))
}

#[must_use]
pub const fn session_idle_window_ms(span_ms: u64, max_idle_ms: u64) -> u64 {
    if span_ms < max_idle_ms {
        span_ms
    } else {
        max_idle_ms
    }
}

#[must_use]
pub const fn is_session_active(revoked_at_ms: Option<i64>) -> bool {
    revoked_at_ms.is_none()
}

#[must_use]
pub const fn is_session_revoked(revoked_at_ms: Option<i64>) -> bool {
    !is_session_active(revoked_at_ms)
}

/// Calculates session age at an injected reference time.
///
/// # Errors
///
/// Returns [`AuthError::ArithmeticOverflow`] when the difference exceeds `i64`.
pub fn session_age_ms(created_at_ms: i64, now_ms: i64) -> AuthResult<i64> {
    now_ms
        .checked_sub(created_at_ms)
        .ok_or(AuthError::ArithmeticOverflow("session age overflowed i64"))
}

#[must_use]
pub fn is_session_idle(last_active_at_ms: i64, idle_timeout_ms: u64, now_ms: i64) -> bool {
    i128::from(now_ms) - i128::from(last_active_at_ms) > i128::from(idle_timeout_ms)
}

#[must_use]
pub fn session_idle_remaining_ms(last_active_at_ms: i64, idle_timeout_ms: u64, now_ms: i64) -> u64 {
    let remaining =
        i128::from(idle_timeout_ms) - (i128::from(now_ms) - i128::from(last_active_at_ms));
    if remaining <= 0 {
        0
    } else {
        u64::try_from(remaining).unwrap_or(u64::MAX)
    }
}

#[must_use]
pub fn select_sessions_for_eviction<T, F>(
    sessions: &[T],
    max_sessions: usize,
    created_at_ms: F,
) -> Vec<&T>
where
    F: Fn(&T) -> i64,
{
    if max_sessions == 0 || sessions.len() <= max_sessions {
        return Vec::new();
    }
    let mut ordered = sessions.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|session| created_at_ms(session));
    ordered.truncate(sessions.len() - max_sessions);
    ordered
}
