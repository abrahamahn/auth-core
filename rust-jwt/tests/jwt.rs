use auth_jwt::{
    Expiration, JwtErrorCode, JwtPayload, JwtRotationConfig, JwtRotationHandler, SignOptions,
    UsedSecret, VerifyOptions, check_token_secret, decode, sign, verify, verify_with_rotation,
};
use serde_json::{Value, json};

const CURRENT_SECRET: &[u8] = b"current-secret-for-auth-core-jwt-tests";
const PREVIOUS_SECRET: &[u8] = b"previous-secret-for-auth-core-jwt-tests";
const NOW: u64 = 1_718_452_800;

fn payload(value: Value) -> JwtPayload {
    match value {
        Value::Object(payload) => payload,
        _ => panic!("object payload"),
    }
}

fn sign_options() -> SignOptions {
    SignOptions {
        expires_in: Some(Expiration::from("15m")),
        issued_at_seconds: Some(NOW),
    }
}

fn verify_options() -> VerifyOptions {
    VerifyOptions {
        current_time_seconds: Some(NOW),
        clock_tolerance_seconds: 0,
    }
}

#[test]
fn signs_decodes_and_verifies_hs256_payloads() {
    let token = sign(
        &payload(json!({ "sub": "user-123", "roles": ["user"] })),
        CURRENT_SECRET,
        &sign_options(),
    )
    .expect("sign");
    let decoded = decode(&token).expect("decode");

    assert_eq!(decoded.get("sub"), Some(&json!("user-123")));
    assert_eq!(decoded.get("iat"), Some(&json!(NOW)));
    assert_eq!(decoded.get("exp"), Some(&json!(NOW + 900)));
    assert_eq!(
        verify(&token, CURRENT_SECRET, verify_options()).expect("verify"),
        decoded
    );
}

#[test]
fn rejects_signature_tampering_and_expiration() {
    let token = sign(
        &payload(json!({ "sub": "user-123" })),
        CURRENT_SECRET,
        &SignOptions {
            expires_in: Some(Expiration::from(60_u64)),
            issued_at_seconds: Some(NOW),
        },
    )
    .expect("sign");

    assert_eq!(
        verify(&token, PREVIOUS_SECRET, verify_options())
            .expect_err("wrong secret")
            .code,
        JwtErrorCode::InvalidSignature
    );
    assert_eq!(
        verify(
            &token,
            CURRENT_SECRET,
            VerifyOptions {
                current_time_seconds: Some(NOW + 60),
                clock_tolerance_seconds: 0,
            }
        )
        .expect_err("expired")
        .code,
        JwtErrorCode::TokenExpired
    );
    verify(
        &token,
        CURRENT_SECRET,
        VerifyOptions {
            current_time_seconds: Some(NOW + 60),
            clock_tolerance_seconds: 1,
        },
    )
    .expect("inside tolerance");
}

#[test]
fn rotation_accepts_previous_secret_only_after_signature_mismatch() {
    let config = JwtRotationConfig {
        secret: CURRENT_SECRET,
        previous_secret: Some(PREVIOUS_SECRET),
    };
    let previous = sign(
        &payload(json!({ "sub": "previous" })),
        PREVIOUS_SECRET,
        &sign_options(),
    )
    .expect("sign");

    assert_eq!(
        verify_with_rotation(&previous, config, verify_options())
            .expect("verify")
            .get("sub"),
        Some(&json!("previous"))
    );
    assert_eq!(
        check_token_secret(&previous, config, verify_options()).used_secret,
        UsedSecret::Previous
    );
    assert_eq!(
        verify_with_rotation("malformed", config, verify_options())
            .expect_err("malformed")
            .code,
        JwtErrorCode::MalformedToken
    );
}

#[test]
fn owned_rotation_handler_hides_key_material() {
    let handler = JwtRotationHandler::new(CURRENT_SECRET, Some(PREVIOUS_SECRET.to_vec()));
    let token = handler
        .sign(&payload(json!({ "sub": "user-123" })), &sign_options())
        .expect("sign");

    assert_eq!(
        handler
            .verify(&token, verify_options())
            .expect("verify")
            .get("sub"),
        Some(&json!("user-123"))
    );
    assert!(handler.has_secret());
    assert!(handler.is_rotating());
}
