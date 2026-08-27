use auth_core::{
    AccountLockoutDecision, AccountLockoutFacts, AccountLockoutPolicy,
    AuthenticationAssuranceLevel, AuthenticationEvidence, AuthenticationFactor,
    DEFAULT_PASSWORD_CONFIG, MfaChallengeDecision, MfaChallengeFactor, MfaChallengeFacts,
    MfaChallengePolicy, MfaChallengeRejectionReason, OneTimeCredentialDecision,
    OneTimeCredentialFacts, OneTimeCredentialPolicy, OneTimeCredentialRejectionReason,
    RefreshCredentialDecision, RefreshCredentialFacts, SessionBindingDecision,
    SessionLifetimePolicy, classify_refresh_credential, credential_epoch_matches,
    derive_authentication_assurance, evaluate_account_lockout, evaluate_mfa_challenge,
    evaluate_one_time_credential, evaluate_session_binding, is_common_password, is_session_idle,
    progressive_delay_ms, select_sessions_for_eviction, session_idle_remaining_ms,
    session_idle_window_ms, session_span_ms, validate_password,
};
use serde_json::Value;

fn number(value: &Value, key: &str) -> i64 {
    value[key]
        .as_i64()
        .unwrap_or_else(|| panic!("{key} must be an i64"))
}

fn unsigned(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} must be a u64"))
}

fn optional_number(value: &Value, key: &str) -> Option<i64> {
    value[key].as_i64()
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value[key].as_str()
}

fn decision_label(decision: RefreshCredentialDecision) -> &'static str {
    match decision {
        RefreshCredentialDecision::Rotate => "rotate",
        RefreshCredentialDecision::RetryCurrent => "retry-current",
        RefreshCredentialDecision::RejectExpired => "reject:expired",
        RefreshCredentialDecision::RevokeFamilyRevoked => "revoke:family-revoked",
        RefreshCredentialDecision::RevokeCredentialReuse => "revoke:credential-reuse",
    }
}

fn binding_label(decision: SessionBindingDecision) -> &'static str {
    match decision {
        SessionBindingDecision::Unbound => "unbound",
        SessionBindingDecision::NotChecked => "not-checked",
        SessionBindingDecision::Match => "match",
        SessionBindingDecision::Mismatch => "mismatch",
    }
}

fn one_time_decision_label(decision: OneTimeCredentialDecision) -> &'static str {
    match decision {
        OneTimeCredentialDecision::Accept { .. } => "accept",
        OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::NotFound,
            ..
        } => "reject:not-found",
        OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::AlreadyConsumed,
            ..
        } => "reject:already-consumed",
        OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::Expired,
            ..
        } => "reject:expired",
        OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::Mismatch,
            ..
        } => "reject:mismatch",
        OneTimeCredentialDecision::Reject {
            reason: OneTimeCredentialRejectionReason::AttemptsExhausted,
            ..
        } => "reject:attempts-exhausted",
    }
}

fn authentication_factor(value: &str) -> AuthenticationFactor {
    match value {
        "password" => AuthenticationFactor::Password,
        "magic-link" => AuthenticationFactor::MagicLink,
        "email-otp" => AuthenticationFactor::EmailOtp,
        "sms-otp" => AuthenticationFactor::SmsOtp,
        "totp" => AuthenticationFactor::Totp,
        "recovery-code" => AuthenticationFactor::RecoveryCode,
        "oauth" => AuthenticationFactor::Oauth,
        "webauthn" => AuthenticationFactor::Webauthn,
        _ => panic!("unknown authentication factor"),
    }
}

fn mfa_challenge_factor(value: &str) -> MfaChallengeFactor {
    match value {
        "email-otp" => MfaChallengeFactor::EmailOtp,
        "sms-otp" => MfaChallengeFactor::SmsOtp,
        "totp" => MfaChallengeFactor::Totp,
        "recovery-code" => MfaChallengeFactor::RecoveryCode,
        "webauthn" => MfaChallengeFactor::Webauthn,
        _ => panic!("unknown MFA challenge factor"),
    }
}

const fn assurance_level_label(level: AuthenticationAssuranceLevel) -> &'static str {
    match level {
        AuthenticationAssuranceLevel::Unauthenticated => "unauthenticated",
        AuthenticationAssuranceLevel::SingleFactor => "single-factor",
        AuthenticationAssuranceLevel::MultiFactor => "multi-factor",
        AuthenticationAssuranceLevel::PhishingResistant => "phishing-resistant",
    }
}

const fn mfa_challenge_decision_label(decision: MfaChallengeDecision) -> &'static str {
    match decision {
        MfaChallengeDecision::Accept => "accept",
        MfaChallengeDecision::Reject(MfaChallengeRejectionReason::Malformed) => "reject:malformed",
        MfaChallengeDecision::Reject(MfaChallengeRejectionReason::PurposeMismatch) => {
            "reject:purpose-mismatch"
        }
        MfaChallengeDecision::Reject(MfaChallengeRejectionReason::FactorNotAllowed) => {
            "reject:factor-not-allowed"
        }
        MfaChallengeDecision::Reject(MfaChallengeRejectionReason::SubjectMismatch) => {
            "reject:subject-mismatch"
        }
        MfaChallengeDecision::Reject(MfaChallengeRejectionReason::CredentialVersionMismatch) => {
            "reject:credential-version-mismatch"
        }
        MfaChallengeDecision::Reject(MfaChallengeRejectionReason::AlreadyConsumed) => {
            "reject:already-consumed"
        }
        MfaChallengeDecision::Reject(MfaChallengeRejectionReason::Expired) => "reject:expired",
    }
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../fixtures/core-vectors.json"))
        .expect("parity fixture must be valid JSON")
}

#[test]
fn password_vectors_match_typescript() {
    let vectors = vectors();
    for vector in vectors["passwords"].as_array().expect("password vectors") {
        let password = vector["password"].as_str().expect("password");
        let inputs = vector["userInputs"]
            .as_array()
            .expect("user inputs")
            .iter()
            .map(|input| input.as_str().expect("user input"))
            .collect::<Vec<_>>();
        let result = validate_password(password, &inputs, DEFAULT_PASSWORD_CONFIG);
        assert_eq!(u64::from(result.score.as_u8()), unsigned(vector, "score"));
        assert_eq!(result.is_valid, vector["valid"].as_bool().expect("valid"));
        assert_eq!(
            is_common_password(password),
            vector["common"].as_bool().expect("common")
        );
    }
}

#[test]
fn refresh_vectors_match_typescript() {
    let vectors = vectors();
    for vector in vectors["refresh"].as_array().expect("refresh vectors") {
        let decision = classify_refresh_credential(RefreshCredentialFacts {
            now_ms: number(vector, "nowMs"),
            expires_at_ms: number(vector, "expiresAtMs"),
            rotated_at_ms: optional_number(vector, "rotatedAtMs"),
            family_revoked_at_ms: optional_number(vector, "familyRevokedAtMs"),
            grace_period_ms: unsigned(vector, "gracePeriodMs"),
        });
        assert_eq!(
            decision_label(decision),
            vector["decision"].as_str().expect("decision")
        );
    }
}

#[test]
fn delay_idle_binding_and_epoch_vectors_match_typescript() {
    let vectors = vectors();
    for vector in vectors["progressiveDelay"]
        .as_array()
        .expect("delay vectors")
    {
        let delay = progressive_delay_ms(
            unsigned(vector, "failedAttempts"),
            optional_number(vector, "mostRecentFailureAtMs"),
            number(vector, "nowMs"),
            unsigned(vector, "baseDelayMs"),
            unsigned(vector, "maxDelayMs"),
        )
        .expect("valid progressive delay vector");
        assert_eq!(delay, unsigned(vector, "expectedMs"));
    }

    for vector in vectors["sessionIdle"].as_array().expect("idle vectors") {
        let last_active_at_ms = number(vector, "lastActiveAtMs");
        let idle_timeout_ms = unsigned(vector, "idleTimeoutMs");
        let now_ms = number(vector, "nowMs");
        assert_eq!(
            is_session_idle(last_active_at_ms, idle_timeout_ms, now_ms),
            vector["idle"].as_bool().expect("idle")
        );
        assert_eq!(
            session_idle_remaining_ms(last_active_at_ms, idle_timeout_ms, now_ms),
            unsigned(vector, "remainingMs")
        );
    }

    for vector in vectors["sessionBindings"]
        .as_array()
        .expect("binding vectors")
    {
        assert_eq!(
            binding_label(evaluate_session_binding(
                optional_string(vector, "expected"),
                optional_string(vector, "presented"),
            )),
            vector["decision"].as_str().expect("binding decision")
        );
    }

    for vector in vectors["credentialEpochs"]
        .as_array()
        .expect("credential epoch vectors")
    {
        assert_eq!(
            credential_epoch_matches(unsigned(vector, "observed"), unsigned(vector, "current")),
            vector["matches"].as_bool().expect("epoch match")
        );
    }
}

#[test]
fn session_lifetime_and_eviction_vectors_match_typescript() {
    let vectors = vectors();
    for vector in vectors["sessionLifetimes"]
        .as_array()
        .expect("session lifetime vectors")
    {
        let policy = SessionLifetimePolicy {
            default_span_ms: unsigned(vector, "defaultSpanMs"),
            remembered_span_ms: unsigned(vector, "rememberedSpanMs"),
            max_idle_ms: unsigned(vector, "maxIdleMs"),
        };
        let span_ms = session_span_ms(
            Some(vector["remembered"].as_bool().expect("remembered")),
            policy,
        );
        assert_eq!(span_ms, unsigned(vector, "expectedSpanMs"));
        assert_eq!(
            session_idle_window_ms(span_ms, policy.max_idle_ms),
            unsigned(vector, "expectedIdleWindowMs")
        );
    }

    let eviction = &vectors["sessionEviction"];
    let sessions = eviction["sessions"]
        .as_array()
        .expect("eviction sessions")
        .iter()
        .map(|session| {
            (
                session["id"].as_str().expect("session id").to_owned(),
                number(session, "createdAtMs"),
            )
        })
        .collect::<Vec<_>>();
    let evicted = select_sessions_for_eviction(
        &sessions,
        usize::try_from(unsigned(eviction, "maxSessions")).expect("max sessions"),
        |session| session.1,
    );
    let evicted_ids = evicted
        .iter()
        .map(|session| session.0.as_str())
        .collect::<Vec<_>>();
    let expected_ids = eviction["expectedIds"]
        .as_array()
        .expect("expected eviction ids")
        .iter()
        .map(|id| id.as_str().expect("eviction id"))
        .collect::<Vec<_>>();
    assert_eq!(evicted_ids, expected_ids);
}

#[test]
fn lockout_vectors_match_typescript() {
    let vectors = vectors();
    for vector in vectors["lockouts"].as_array().expect("lockout vectors") {
        let decision = evaluate_account_lockout(
            AccountLockoutFacts {
                now_ms: number(vector, "nowMs"),
                failed_attempts: unsigned(vector, "failedAttempts"),
                most_recent_failure_at_ms: optional_number(vector, "mostRecentFailureAtMs"),
            },
            AccountLockoutPolicy {
                max_attempts: unsigned(vector, "maxAttempts"),
                lockout_duration_ms: unsigned(vector, "lockoutDurationMs"),
            },
        )
        .expect("valid lockout vector");
        let (is_locked, failed_attempts, remaining_ms, locked_until_ms) = match decision {
            AccountLockoutDecision::Unlocked { failed_attempts } => {
                (false, failed_attempts, None, None)
            }
            AccountLockoutDecision::Locked {
                failed_attempts,
                remaining_ms,
                locked_until_ms,
            } => (true, failed_attempts, remaining_ms, locked_until_ms),
        };
        assert_eq!(is_locked, vector["isLocked"].as_bool().expect("locked"));
        assert_eq!(failed_attempts, unsigned(vector, "failedAttempts"));
        assert_eq!(
            remaining_ms,
            vector["remainingMs"].as_u64(),
            "remaining lockout duration"
        );
        assert_eq!(
            locked_until_ms,
            optional_number(vector, "lockedUntilMs"),
            "lockout deadline"
        );
    }
}

#[test]
fn one_time_credential_vectors_match_typescript() {
    let vectors = vectors();
    for vector in vectors["oneTimeCredentials"]
        .as_array()
        .expect("one-time credential vectors")
    {
        let decision = evaluate_one_time_credential(
            OneTimeCredentialFacts {
                exists: vector["exists"].as_bool().expect("exists"),
                now_ms: number(vector, "nowMs"),
                expires_at_ms: optional_number(vector, "expiresAtMs"),
                consumed_at_ms: optional_number(vector, "consumedAtMs"),
                failed_attempts: unsigned(vector, "failedAttempts"),
                presented_matches: vector["presentedMatches"]
                    .as_bool()
                    .expect("presented matches"),
            },
            OneTimeCredentialPolicy {
                max_failed_attempts: unsigned(vector, "maxFailedAttempts"),
            },
        )
        .expect("valid one-time credential vector");
        let (consume, failed_attempts) = match decision {
            OneTimeCredentialDecision::Accept {
                consume,
                failed_attempts,
            }
            | OneTimeCredentialDecision::Reject {
                consume,
                failed_attempts,
                ..
            } => (consume, failed_attempts),
        };
        assert_eq!(
            one_time_decision_label(decision),
            vector["decision"].as_str().expect("decision")
        );
        assert_eq!(consume, vector["consume"].as_bool().expect("consume"));
        assert_eq!(failed_attempts, unsigned(vector, "resultFailedAttempts"));
    }
}

#[test]
fn mfa_vectors_match_typescript() {
    let vectors = vectors();
    for vector in vectors["mfaAssurance"]
        .as_array()
        .expect("MFA assurance vectors")
    {
        let evidence = vector["evidence"]
            .as_array()
            .expect("MFA evidence")
            .iter()
            .map(|item| AuthenticationEvidence {
                factor: authentication_factor(item["factor"].as_str().expect("factor")),
                verified_at_ms: number(item, "verifiedAtMs"),
                user_verified: item["userVerified"].as_bool().expect("user verified"),
            })
            .collect::<Vec<_>>();
        let assurance = derive_authentication_assurance(&evidence);
        assert_eq!(
            assurance_level_label(assurance.level),
            vector["level"].as_str().expect("assurance level")
        );
        assert_eq!(
            assurance.authenticated_at_ms,
            optional_number(vector, "authenticatedAtMs")
        );
        assert_eq!(
            u64::try_from(assurance.factor_count).expect("factor count fits u64"),
            unsigned(vector, "factorCount")
        );
    }

    for vector in vectors["mfaChallenges"]
        .as_array()
        .expect("MFA challenge vectors")
    {
        let allowed_purposes = vector["allowedPurposes"]
            .as_array()
            .expect("allowed purposes")
            .iter()
            .map(|purpose| purpose.as_str().expect("purpose"))
            .collect::<Vec<_>>();
        let allowed_factors = vector["allowedFactors"]
            .as_array()
            .expect("allowed factors")
            .iter()
            .map(|factor| mfa_challenge_factor(factor.as_str().expect("factor")))
            .collect::<Vec<_>>();
        let decision = evaluate_mfa_challenge(
            MfaChallengeFacts {
                purpose: optional_string(vector, "purpose"),
                subject: optional_string(vector, "subject"),
                factor: optional_string(vector, "factor").map(mfa_challenge_factor),
                credential_version: vector["credentialVersion"].as_u64(),
                expires_at_ms: optional_number(vector, "expiresAtMs"),
                consumed_at_ms: optional_number(vector, "consumedAtMs"),
            },
            MfaChallengePolicy {
                allowed_purposes: &allowed_purposes,
                allowed_factors: &allowed_factors,
                expected_subject: optional_string(vector, "expectedSubject"),
                current_credential_version: vector["currentCredentialVersion"].as_u64(),
                now_ms: optional_number(vector, "nowMs"),
            },
        )
        .expect("valid MFA challenge vector");
        assert_eq!(
            mfa_challenge_decision_label(decision),
            vector["decision"].as_str().expect("MFA challenge decision")
        );
    }
}
