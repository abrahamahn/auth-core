use auth_core::{
    AccountLockoutDecision, AccountLockoutFacts, AccountLockoutPolicy, AuthError,
    AuthorizationDecision, DEFAULT_PASSWORD_CONFIG, ExpiringReplayGuard, PasswordScore, RbacError,
    RbacPolicy, RefreshCredentialFacts, RoleDefinition, SessionBindingDecision,
    credential_epoch_matches, evaluate_account_lockout, evaluate_session_binding,
    has_repeated_pattern, is_lockout_threshold_reached, is_refresh_retry_eligible,
    progressive_delay_ms, select_sessions_for_eviction, validate_password,
};

#[test]
fn repeated_password_patterns_cannot_gain_strength_from_length() {
    for password in [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "passwordpasswordpasswordpassword",
        "qwertyqwertyqwertyqwerty",
    ] {
        let result = validate_password(password, &[], DEFAULT_PASSWORD_CONFIG);
        assert!(has_repeated_pattern(password));
        assert!(!result.is_valid);
        assert!(result.score < PasswordScore::Strong);
        assert_ne!(result.crack_time_display, "centuries");
    }
}

#[test]
fn refresh_retry_requires_the_same_credential_epoch() {
    let facts = RefreshCredentialFacts {
        now_ms: 10_000,
        expires_at_ms: 20_000,
        rotated_at_ms: Some(9_500),
        family_revoked_at_ms: None,
        grace_period_ms: 1_000,
    };
    assert!(credential_epoch_matches(4, 4));
    assert!(is_refresh_retry_eligible(facts, 4, 4));
    assert!(!is_refresh_retry_eligible(facts, 4, 5));
}

#[test]
fn binding_lockout_and_session_eviction_are_deterministic() {
    assert_eq!(
        evaluate_session_binding(Some("browser-a"), None),
        SessionBindingDecision::NotChecked
    );
    assert_eq!(
        evaluate_account_lockout(
            AccountLockoutFacts {
                now_ms: 10_000,
                failed_attempts: 5,
                most_recent_failure_at_ms: Some(9_000),
            },
            AccountLockoutPolicy {
                max_attempts: 5,
                lockout_duration_ms: 5_000,
            },
        )
        .expect("valid lockout facts"),
        AccountLockoutDecision::Locked {
            failed_attempts: 5,
            remaining_ms: Some(4_000),
            locked_until_ms: Some(14_000),
        }
    );

    let sessions = [("newest", 30), ("oldest", 10), ("middle", 20)];
    let evicted = select_sessions_for_eviction(&sessions, 2, |session| session.1);
    assert_eq!(evicted, vec![&sessions[1]]);
}

#[test]
fn lockout_boundaries_and_invalid_policies_are_explicit() {
    assert_eq!(
        evaluate_account_lockout(
            AccountLockoutFacts {
                now_ms: 14_000,
                failed_attempts: 5,
                most_recent_failure_at_ms: Some(9_000),
            },
            AccountLockoutPolicy {
                max_attempts: 5,
                lockout_duration_ms: 5_000,
            },
        )
        .expect("valid lockout facts"),
        AccountLockoutDecision::Unlocked { failed_attempts: 5 }
    );
    assert_eq!(
        progressive_delay_ms(4, Some(10_500), 10_000, 1_000, 5_000)
            .expect("valid progressive delay"),
        5_000
    );
    assert_eq!(
        is_lockout_threshold_reached(1, 0),
        Err(AuthError::InvalidValue("max_attempts must be positive"))
    );
    assert_eq!(
        progressive_delay_ms(1, Some(10_000), 10_000, 2_000, 1_000),
        Err(AuthError::InvalidValue(
            "max_delay_ms must be at least base_delay_ms"
        ))
    );
}

#[test]
fn rbac_resolves_transitive_inheritance_and_denials() {
    let policy = RbacPolicy::new([
        RoleDefinition::new("viewer").grants(["document:read"]),
        RoleDefinition::new("editor")
            .grants(["document:write"])
            .inherits(["viewer"]),
        RoleDefinition::new("admin")
            .grants(["users:manage"])
            .inherits(["editor"]),
    ])
    .expect("valid role policy");

    assert!(policy.has_role("admin", "viewer"));
    assert!(policy.has_permission("admin", "document:read"));
    assert!(policy.has_every_permission("editor", ["document:read", "document:write"]));
    assert!(policy.has_any_permission("viewer", ["document:write", "document:read"]));
    assert_eq!(
        policy.evaluate("viewer", "document:write"),
        AuthorizationDecision::MissingPermission
    );
    assert_eq!(
        policy.evaluate("missing", "document:read"),
        AuthorizationDecision::UnknownRole
    );
}

#[test]
fn rbac_rejects_invalid_role_graphs() {
    assert_eq!(
        RbacPolicy::new([RoleDefinition::new("member"), RoleDefinition::new("member")]),
        Err(RbacError::DuplicateRole("member".to_owned()))
    );
    assert_eq!(
        RbacPolicy::new([RoleDefinition::new("member").inherits(["missing"])]),
        Err(RbacError::UnknownInheritedRole("missing".to_owned()))
    );
    assert_eq!(
        RbacPolicy::new([
            RoleDefinition::new("left").inherits(["right"]),
            RoleDefinition::new("right").inherits(["left"]),
        ]),
        Err(RbacError::InheritanceCycle("left".to_owned()))
    );
}

#[test]
fn replay_guard_expires_and_clears_challenge_ids() {
    let mut guard = ExpiringReplayGuard::new();
    guard
        .burn("challenge-a", 500, 1_000)
        .expect("valid challenge deadline");
    assert!(guard.is_burned(&"challenge-a", 1_499));
    assert!(!guard.is_burned(&"challenge-b", 1_499));
    assert!(!guard.is_burned(&"challenge-a", 1_500));
    assert!(guard.is_empty(1_500));

    guard
        .burn("active", 100, 1_000)
        .expect("valid challenge deadline");
    guard.clear();
    assert!(!guard.is_burned(&"active", 1_001));
}
