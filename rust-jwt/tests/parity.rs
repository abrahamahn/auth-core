use auth_jwt::{VerifyOptions, verify};
use serde_json::Value;

#[test]
fn verifies_the_shared_typescript_hs256_vector() {
    let vectors: Value =
        serde_json::from_str(include_str!("../fixtures/jwt-vectors.json")).expect("valid vectors");
    let vector = &vectors["hs256"];
    let secret = vector["secret"].as_str().expect("secret");
    let token = vector["token"].as_str().expect("token");
    let issued_at = vector["issuedAt"].as_u64().expect("issued at");
    let payload = verify(
        token,
        secret.as_bytes(),
        VerifyOptions {
            current_time_seconds: Some(issued_at),
            clock_tolerance_seconds: 0,
        },
    )
    .expect("verify shared token");

    assert_eq!(payload.get("sub"), Some(&vector["payload"]["sub"]));
    assert_eq!(payload.get("scope"), Some(&vector["payload"]["scope"]));
    assert_eq!(payload.get("iat"), Some(&vector["issuedAt"]));
    assert_eq!(payload.get("exp"), Some(&vector["expiresAt"]));
}
