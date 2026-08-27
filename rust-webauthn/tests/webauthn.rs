use std::time::Duration;

use auth_webauthn::{AuthWebauthnConfig, AuthWebauthnServer, Url, Uuid};

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
