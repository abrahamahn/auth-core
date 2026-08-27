use crate::{AuthError, AuthResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneTimeCredentialFacts {
    pub exists: bool,
    pub now_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub consumed_at_ms: Option<i64>,
    pub failed_attempts: u64,
    pub presented_matches: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneTimeCredentialPolicy {
    pub max_failed_attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneTimeCredentialRejectionReason {
    NotFound,
    AlreadyConsumed,
    Expired,
    Mismatch,
    AttemptsExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneTimeCredentialDecision {
    Accept {
        consume: bool,
        failed_attempts: u64,
    },
    Reject {
        reason: OneTimeCredentialRejectionReason,
        consume: bool,
        failed_attempts: u64,
    },
}

/// Evaluates a single-use credential without performing persistence or comparison itself.
///
/// Callers are responsible for constant-time verification where applicable and for applying the
/// returned attempt/consumption mutation atomically.
///
/// # Errors
///
/// Returns [`AuthError::InvalidValue`] when the attempt threshold is zero or an existing
/// credential has no expiration timestamp, and [`AuthError::ArithmeticOverflow`] when the failed
/// attempt counter cannot be incremented.
pub fn evaluate_one_time_credential(
    facts: OneTimeCredentialFacts,
    policy: OneTimeCredentialPolicy,
) -> AuthResult<OneTimeCredentialDecision> {
    if policy.max_failed_attempts == 0 {
        return Err(AuthError::InvalidValue(
            "max_failed_attempts must be positive",
        ));
    }
    if !facts.exists {
        return Ok(OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::NotFound,
            consume: false,
            failed_attempts: facts.failed_attempts,
        });
    }
    let Some(expires_at_ms) = facts.expires_at_ms else {
        return Err(AuthError::InvalidValue(
            "expires_at_ms is required for an existing credential",
        ));
    };
    if facts.consumed_at_ms.is_some() {
        return Ok(OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::AlreadyConsumed,
            consume: false,
            failed_attempts: facts.failed_attempts,
        });
    }
    if facts.now_ms >= expires_at_ms {
        return Ok(OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::Expired,
            consume: false,
            failed_attempts: facts.failed_attempts,
        });
    }
    if facts.failed_attempts >= policy.max_failed_attempts {
        return Ok(OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::AttemptsExhausted,
            consume: true,
            failed_attempts: facts.failed_attempts,
        });
    }
    if facts.presented_matches {
        return Ok(OneTimeCredentialDecision::Accept {
            consume: true,
            failed_attempts: facts.failed_attempts,
        });
    }

    let failed_attempts =
        facts
            .failed_attempts
            .checked_add(1)
            .ok_or(AuthError::ArithmeticOverflow(
                "failed attempt counter overflowed u64",
            ))?;
    let exhausted = failed_attempts >= policy.max_failed_attempts;
    Ok(OneTimeCredentialDecision::Reject {
        reason: if exhausted {
            OneTimeCredentialRejectionReason::AttemptsExhausted
        } else {
            OneTimeCredentialRejectionReason::Mismatch
        },
        consume: exhausted,
        failed_attempts,
    })
}
