use std::time::Duration;

use auth_webauthn::{
    AuthWebauthnConfig, AuthWebauthnServer, InMemoryWebauthnCeremonyStore, Url, Uuid,
    WebauthnCeremonyKind, WebauthnCeremonyStoreError,
};

#[test]
fn validates_relying_party_and_starts_serializable_registration() {
    let origin = Url::parse("https://login.example.com").expect("valid origin");
    let server = AuthWebauthnServer::new(AuthWebauthnConfig {
        rp_name: "Example",
        rp_id: "example.com",
        rp_origin: &origin,
        timeout: Some(Duration::from_secs(120)),
    })
    .expect("valid relying party");

    let (options, state) = server
        .start_registration(Uuid::new_v4(), "user@example.com", "Example User", None)
        .expect("registration options");
    let options_json = serde_json::to_value(options).expect("serializable browser options");
    let state_json = serde_json::to_value(state).expect("serializable server-side state");
    assert!(options_json["publicKey"]["challenge"].is_string());
    assert!(state_json.is_object());
    assert_eq!(server.allowed_origins(), &[origin]);
}

#[test]
fn rejects_an_origin_outside_the_relying_party() {
    let origin = Url::parse("https://unrelated.test").expect("valid URL");
    let result = AuthWebauthnServer::new(AuthWebauthnConfig {
        rp_name: "Example",
        rp_id: "example.com",
        rp_origin: &origin,
        timeout: None,
    });
    assert!(result.is_err());
}

#[test]
fn ceremony_store_consumes_opaque_state_exactly_once() {
    let mut store = InMemoryWebauthnCeremonyStore::new(500).expect("valid TTL");
    store
        .put(
            "reg:user-1",
            WebauthnCeremonyKind::Registration,
            "opaque-registration-state",
            Some("user-1".to_owned()),
            1_000,
        )
        .expect("stored ceremony");

    let ceremony = store
        .consume("reg:user-1", WebauthnCeremonyKind::Registration, 1_499)
        .expect("single use");
    assert_eq!(ceremony.state, "opaque-registration-state");
    assert_eq!(ceremony.expires_at_ms, 1_500);
    assert_eq!(ceremony.subject_id.as_deref(), Some("user-1"));
    assert_eq!(
        store
            .consume("reg:user-1", WebauthnCeremonyKind::Registration, 1_499,)
            .unwrap_err(),
        WebauthnCeremonyStoreError::Missing
    );
}

#[test]
fn ceremony_store_deletes_expired_and_mismatched_state() {
    let mut store = InMemoryWebauthnCeremonyStore::new(500).expect("valid TTL");
    store
        .put(
            "auth:one",
            WebauthnCeremonyKind::Authentication,
            "state-one",
            None,
            1_000,
        )
        .expect("stored ceremony");
    assert_eq!(
        store
            .consume("auth:one", WebauthnCeremonyKind::Registration, 1_001,)
            .unwrap_err(),
        WebauthnCeremonyStoreError::KindMismatch
    );
    assert!(store.is_empty());

    store
        .put(
            "auth:two",
            WebauthnCeremonyKind::Authentication,
            "state-two",
            None,
            1_000,
        )
        .expect("stored ceremony");
    assert_eq!(
        store
            .consume("auth:two", WebauthnCeremonyKind::Authentication, 1_500,)
            .unwrap_err(),
        WebauthnCeremonyStoreError::Expired
    );
    assert!(store.is_empty());

    assert_eq!(
        InMemoryWebauthnCeremonyStore::<()>::new(0).unwrap_err(),
        WebauthnCeremonyStoreError::InvalidTtl
    );
    let mut overflowing = InMemoryWebauthnCeremonyStore::new(2).expect("valid TTL");
    assert_eq!(
        overflowing
            .put(
                "auth:overflow",
                WebauthnCeremonyKind::Authentication,
                (),
                None,
                u64::MAX - 1,
            )
            .unwrap_err(),
        WebauthnCeremonyStoreError::ExpiryOverflow
    );
    assert!(overflowing.is_empty());
}
