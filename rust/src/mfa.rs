use crate::{AuthError, AuthResult};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthenticationFactor {
    Password,
    MagicLink,
    EmailOtp,
    SmsOtp,
    Totp,
    RecoveryCode,
    Oauth,
    Webauthn,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MfaChallengeFactor {
    EmailOtp,
    SmsOtp,
    Totp,
    RecoveryCode,
    Webauthn,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthenticationAssuranceLevel {
    Unauthenticated,
    SingleFactor,
    MultiFactor,
    PhishingResistant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationEvidence {
    pub factor: AuthenticationFactor,
    pub verified_at_ms: i64,
    pub user_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationAssurance {
    pub level: AuthenticationAssuranceLevel,
    pub authenticated_at_ms: Option<i64>,
    pub factor_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepUpPolicy<'a> {
    pub minimum_level: AuthenticationAssuranceLevel,
    pub max_age_ms: Option<u64>,
    pub required_factors: &'a [AuthenticationFactor],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepUpChallengeReason {
    Unauthenticated,
    InsufficientAssurance,
    RequiredFactorMissing,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepUpDecision {
    Allow {
        assurance: AuthenticationAssurance,
    },
    Challenge {
        reason: StepUpChallengeReason,
        assurance: AuthenticationAssurance,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MfaChallengeFacts<'a> {
    pub purpose: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub factor: Option<MfaChallengeFactor>,
    pub credential_version: Option<u64>,
    pub expires_at_ms: Option<i64>,
    pub consumed_at_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MfaChallengePolicy<'a> {
    pub allowed_purposes: &'a [&'a str],
    pub allowed_factors: &'a [MfaChallengeFactor],
    pub expected_subject: Option<&'a str>,
    pub current_credential_version: Option<u64>,
    pub now_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaChallengeRejectionReason {
    Malformed,
    PurposeMismatch,
    FactorNotAllowed,
    SubjectMismatch,
    CredentialVersionMismatch,
    AlreadyConsumed,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaChallengeDecision {
    Accept,
    Reject(MfaChallengeRejectionReason),
}

const FACTOR_COUNT: usize = 8;

const fn factor_index(factor: AuthenticationFactor) -> usize {
    match factor {
        AuthenticationFactor::Password => 0,
        AuthenticationFactor::MagicLink => 1,
        AuthenticationFactor::EmailOtp => 2,
        AuthenticationFactor::SmsOtp => 3,
        AuthenticationFactor::Totp => 4,
        AuthenticationFactor::RecoveryCode => 5,
        AuthenticationFactor::Oauth => 6,
        AuthenticationFactor::Webauthn => 7,
    }
}

fn latest_evidence(evidence: &[AuthenticationEvidence]) -> ([Option<i64>; FACTOR_COUNT], bool) {
    let mut latest = [None; FACTOR_COUNT];
    let mut latest_webauthn_user_verified_at = None;
    for item in evidence {
        let index = factor_index(item.factor);
        if latest[index].is_none_or(|current| item.verified_at_ms > current) {
            latest[index] = Some(item.verified_at_ms);
        }
        if item.factor == AuthenticationFactor::Webauthn && item.user_verified {
            latest_webauthn_user_verified_at = Some(
                latest_webauthn_user_verified_at.map_or(item.verified_at_ms, |current: i64| {
                    current.max(item.verified_at_ms)
                }),
            );
        }
    }
    (latest, latest_webauthn_user_verified_at.is_some())
}

/// Derives the strongest assurance supported by the supplied verified evidence.
#[must_use]
pub fn derive_authentication_assurance(
    evidence: &[AuthenticationEvidence],
) -> AuthenticationAssurance {
    let (latest, webauthn_user_verified) = latest_evidence(evidence);
    let mut timestamps = latest.iter().flatten().copied().collect::<Vec<_>>();
    timestamps.sort_unstable_by(|left, right| right.cmp(left));
    if timestamps.is_empty() {
        return AuthenticationAssurance {
            level: AuthenticationAssuranceLevel::Unauthenticated,
            authenticated_at_ms: None,
            factor_count: 0,
        };
    }

    if webauthn_user_verified {
        return AuthenticationAssurance {
            level: AuthenticationAssuranceLevel::PhishingResistant,
            authenticated_at_ms: evidence
                .iter()
                .filter(|item| item.factor == AuthenticationFactor::Webauthn && item.user_verified)
                .map(|item| item.verified_at_ms)
                .max(),
            factor_count: timestamps.len(),
        };
    }

    if timestamps.len() >= 2 {
        return AuthenticationAssurance {
            level: AuthenticationAssuranceLevel::MultiFactor,
            authenticated_at_ms: timestamps.get(1).copied(),
            factor_count: timestamps.len(),
        };
    }

    AuthenticationAssurance {
        level: AuthenticationAssuranceLevel::SingleFactor,
        authenticated_at_ms: timestamps.first().copied(),
        factor_count: 1,
    }
}

/// Determines whether existing authentication evidence satisfies a step-up policy.
///
/// # Errors
///
/// Returns [`AuthError::ArithmeticOverflow`] when the freshness cutoff cannot be represented.
pub fn evaluate_step_up(
    evidence: &[AuthenticationEvidence],
    now_ms: i64,
    policy: StepUpPolicy<'_>,
) -> AuthResult<StepUpDecision> {
    let (latest, _) = latest_evidence(evidence);
    let assurance = derive_authentication_assurance(evidence);
    if assurance.level == AuthenticationAssuranceLevel::Unauthenticated {
        return Ok(StepUpDecision::Challenge {
            reason: StepUpChallengeReason::Unauthenticated,
            assurance,
        });
    }

    if policy
        .required_factors
        .iter()
        .any(|factor| latest[factor_index(*factor)].is_none())
    {
        return Ok(StepUpDecision::Challenge {
            reason: StepUpChallengeReason::RequiredFactorMissing,
            assurance,
        });
    }
    if assurance.level < policy.minimum_level {
        return Ok(StepUpDecision::Challenge {
            reason: StepUpChallengeReason::InsufficientAssurance,
            assurance,
        });
    }

    if let Some(max_age_ms) = policy.max_age_ms {
        let max_age_ms = i64::try_from(max_age_ms)
            .map_err(|_| AuthError::ArithmeticOverflow("max_age_ms exceeds i64"))?;
        let cutoff_ms = now_ms
            .checked_sub(max_age_ms)
            .ok_or(AuthError::ArithmeticOverflow(
                "step-up cutoff overflowed i64",
            ))?;
        let assurance_is_stale = assurance
            .authenticated_at_ms
            .is_none_or(|authenticated_at_ms| authenticated_at_ms < cutoff_ms);
        let required_factor_is_stale = policy.required_factors.iter().any(|factor| {
            latest[factor_index(*factor)].is_none_or(|verified_at_ms| verified_at_ms < cutoff_ms)
        });
        if assurance_is_stale || required_factor_is_stale {
            return Ok(StepUpDecision::Challenge {
                reason: StepUpChallengeReason::Stale,
                assurance,
            });
        }
    }

    Ok(StepUpDecision::Allow { assurance })
}

/// Selects the first enrolled challenge factor in application-supplied preference order.
#[must_use]
pub fn select_mfa_challenge_factor(
    enrolled_factors: &[MfaChallengeFactor],
    preferred_factors: &[MfaChallengeFactor],
) -> Option<MfaChallengeFactor> {
    preferred_factors
        .iter()
        .find(|factor| enrolled_factors.contains(factor))
        .copied()
}

/// Evaluates already-decoded MFA challenge claims without owning token cryptography.
///
/// # Errors
///
/// Returns [`AuthError::InvalidValue`] when a policy has no allowed purpose or factor, or when an
/// expiration timestamp is supplied without the current time.
pub fn evaluate_mfa_challenge(
    facts: MfaChallengeFacts<'_>,
    policy: MfaChallengePolicy<'_>,
) -> AuthResult<MfaChallengeDecision> {
    if policy.allowed_purposes.is_empty() || policy.allowed_factors.is_empty() {
        return Err(AuthError::InvalidValue(
            "MFA challenge policy must allow a purpose and factor",
        ));
    }
    let (Some(purpose), Some(subject), Some(factor), Some(credential_version)) = (
        facts.purpose,
        facts.subject,
        facts.factor,
        facts.credential_version,
    ) else {
        return Ok(MfaChallengeDecision::Reject(
            MfaChallengeRejectionReason::Malformed,
        ));
    };
    if purpose.is_empty() || subject.is_empty() {
        return Ok(MfaChallengeDecision::Reject(
            MfaChallengeRejectionReason::Malformed,
        ));
    }
    if !policy.allowed_purposes.contains(&purpose) {
        return Ok(MfaChallengeDecision::Reject(
            MfaChallengeRejectionReason::PurposeMismatch,
        ));
    }
    if !policy.allowed_factors.contains(&factor) {
        return Ok(MfaChallengeDecision::Reject(
            MfaChallengeRejectionReason::FactorNotAllowed,
        ));
    }
    if policy
        .expected_subject
        .is_some_and(|expected| subject != expected)
    {
        return Ok(MfaChallengeDecision::Reject(
            MfaChallengeRejectionReason::SubjectMismatch,
        ));
    }
    if policy
        .current_credential_version
        .is_some_and(|current| credential_version != current)
    {
        return Ok(MfaChallengeDecision::Reject(
            MfaChallengeRejectionReason::CredentialVersionMismatch,
        ));
    }
    if facts.consumed_at_ms.is_some() {
        return Ok(MfaChallengeDecision::Reject(
            MfaChallengeRejectionReason::AlreadyConsumed,
        ));
    }
    if let Some(expires_at_ms) = facts.expires_at_ms {
        let Some(now_ms) = policy.now_ms else {
            return Err(AuthError::InvalidValue(
                "now_ms is required when expires_at_ms is present",
            ));
        };
        if now_ms >= expires_at_ms {
            return Ok(MfaChallengeDecision::Reject(
                MfaChallengeRejectionReason::Expired,
            ));
        }
    }

    Ok(MfaChallengeDecision::Accept)
}
