use auth_totp::{
    TotpAlgorithm, TotpConfig, create_totp_uri, format_recovery_code, generate_totp_code,
    verify_totp_code,
};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../fixtures/totp-vectors.json"))
        .expect("TOTP parity fixture must be valid JSON")
}

fn config(vector: &Value) -> TotpConfig {
    TotpConfig {
        algorithm: match vector["algorithm"].as_str().expect("algorithm") {
            "SHA1" => TotpAlgorithm::Sha1,
            "SHA256" => TotpAlgorithm::Sha256,
            "SHA512" => TotpAlgorithm::Sha512,
            value => panic!("unsupported test algorithm: {value}"),
        },
        digits: u32::try_from(vector["digits"].as_u64().expect("digits")).expect("u32 digits"),
        period_seconds: vector["periodSeconds"].as_u64().expect("period"),
    }
}

#[test]
fn shared_rfc_vectors_match_typescript() {
    for vector in vectors()["totp"].as_array().expect("TOTP vectors") {
        let secret = vector["secretBase32"].as_str().expect("secret");
        let timestamp_ms = vector["timestampMs"].as_u64().expect("timestamp");
        let expected = vector["code"].as_str().expect("code");
        let config = config(vector);
        assert_eq!(
            generate_totp_code(secret, timestamp_ms, config).expect("valid TOTP vector"),
            expected
        );
        assert!(
            verify_totp_code(secret, expected, timestamp_ms, 0, config)
                .expect("valid verification vector")
        );
    }
}

#[test]
fn verification_supports_bounded_clock_drift() {
    let vector = &vectors()["totp"][0];
    let secret = vector["secretBase32"].as_str().expect("secret");
    let timestamp_ms = vector["timestampMs"].as_u64().expect("timestamp");
    let code = vector["code"].as_str().expect("code");
    assert!(
        verify_totp_code(secret, code, timestamp_ms + 30_000, 1, config(vector))
            .expect("valid drift window")
    );
    assert!(
        !verify_totp_code(secret, "not-a-code", timestamp_ms, 0, config(vector))
            .expect("malformed code is a denial")
    );
}

#[test]
fn enrollment_uris_and_recovery_codes_are_canonical() {
    let vector = &vectors()["totp"][0];
    let uri = create_totp_uri(
        vector["secretBase32"].as_str().expect("secret"),
        "Example App",
        "user@example.com",
        config(vector),
    )
    .expect("valid enrollment URI");
    assert!(uri.starts_with("otpauth://totp/Example%20App:user%40example%2Ecom"));
    assert_eq!(
        format_recovery_code(&[0xab, 0xcd, 0x12, 0x34], 4).expect("valid recovery entropy"),
        "ABCD-1234"
    );
}
