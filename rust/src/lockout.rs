use crate::{AuthError, AuthResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountLockoutFacts {
    pub now_ms: i64,
    pub failed_attempts: u64,
    pub most_recent_failure_at_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountLockoutPolicy {
    pub max_attempts: u64,
    pub lockout_duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountLockoutDecision {
    Unlocked {
        failed_attempts: u64,
    },
    Locked {
        failed_attempts: u64,
        remaining_ms: Option<u64>,
        locked_until_ms: Option<i64>,
    },
}

/// Returns whether the configured failed-attempt threshold has been reached.
///
/// # Errors
///
/// Returns [`AuthError::InvalidValue`] when `max_attempts` is zero.
pub fn is_lockout_threshold_reached(failed_attempts: u64, max_attempts: u64) -> AuthResult<bool> {
    if max_attempts == 0 {
        return Err(AuthError::InvalidValue("max_attempts must be positive"));
    }
    Ok(failed_attempts >= max_attempts)
}

/// Calculates the unserved portion of a capped exponential authentication delay.
///
/// # Errors
///
/// Returns [`AuthError::InvalidValue`] when the maximum delay is below the base delay.
pub fn progressive_delay_ms(
    failed_attempts: u64,
    most_recent_failure_at_ms: Option<i64>,
    now_ms: i64,
    base_delay_ms: u64,
    max_delay_ms: u64,
) -> AuthResult<u64> {
    if max_delay_ms < base_delay_ms {
        return Err(AuthError::InvalidValue(
            "max_delay_ms must be at least base_delay_ms",
        ));
    }
    let Some(most_recent_failure_at_ms) = most_recent_failure_at_ms else {
        return Ok(0);
    };
    if failed_attempts == 0 || base_delay_ms == 0 {
        return Ok(0);
    }
    let shift = u32::try_from(failed_attempts - 1).unwrap_or(u32::MAX);
    let multiplier = 1_u128.checked_shl(shift).unwrap_or(u128::MAX);
    let full_delay = u128::from(base_delay_ms)
        .saturating_mul(multiplier)
        .min(u128::from(max_delay_ms));
    let elapsed = (i128::from(now_ms) - i128::from(most_recent_failure_at_ms)).max(0);
    let remaining = i128::try_from(full_delay).unwrap_or(i128::MAX) - elapsed;
    if remaining <= 0 {
        Ok(0)
    } else {
        Ok(u64::try_from(remaining).unwrap_or(u64::MAX))
    }
}

/// Evaluates lockout state and, when known, the deterministic unlock deadline.
///
/// # Errors
///
/// Returns [`AuthError`] for an invalid threshold or timestamp arithmetic overflow.
pub fn evaluate_account_lockout(
    facts: AccountLockoutFacts,
    policy: AccountLockoutPolicy,
) -> AuthResult<AccountLockoutDecision> {
    if !is_lockout_threshold_reached(facts.failed_attempts, policy.max_attempts)? {
        return Ok(AccountLockoutDecision::Unlocked {
            failed_attempts: facts.failed_attempts,
        });
    }
    let Some(most_recent_failure_at_ms) = facts.most_recent_failure_at_ms else {
        return Ok(AccountLockoutDecision::Locked {
            failed_attempts: facts.failed_attempts,
            remaining_ms: None,
            locked_until_ms: None,
        });
    };
    let duration = i64::try_from(policy.lockout_duration_ms)
        .map_err(|_| AuthError::ArithmeticOverflow("lockout duration exceeds i64"))?;
    let locked_until_ms =
        most_recent_failure_at_ms
            .checked_add(duration)
            .ok_or(AuthError::ArithmeticOverflow(
                "lockout deadline overflowed i64",
            ))?;
    if locked_until_ms <= facts.now_ms {
        return Ok(AccountLockoutDecision::Unlocked {
            failed_attempts: facts.failed_attempts,
        });
    }
    let remaining = i128::from(locked_until_ms) - i128::from(facts.now_ms);
    Ok(AccountLockoutDecision::Locked {
        failed_attempts: facts.failed_attempts,
        remaining_ms: Some(u64::try_from(remaining).unwrap_or(u64::MAX)),
        locked_until_ms: Some(locked_until_ms),
    })
}
