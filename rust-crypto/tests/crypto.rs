use auth_crypto::{
    contextual_device_fingerprint, decrypt_secret, encrypt_secret, generate_base64_url_token,
    generate_hex_token, generate_numeric_code, generate_opaque_token, sha256_token_digest,
    stable_device_fingerprint,
};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../fixtures/crypto-vectors.json"))
        .expect("crypto parity fixture must be valid JSON")
}

#[test]
fn digests_and_fingerprints_match_typescript() {
    let vectors = vectors();
    for vector in vectors["tokenDigests"].as_array().expect("digest vectors") {
        assert_eq!(
            sha256_token_digest(vector["input"].as_str().expect("digest input")),
            vector["digest"].as_str().expect("digest")
        );
    }
    let fingerprints = &vectors["fingerprints"];
    assert_eq!(
        stable_device_fingerprint(fingerprints["deviceId"].as_str().expect("device id")),
        fingerprints["stable"].as_str().expect("stable fingerprint")
    );
    assert_eq!(
        contextual_device_fingerprint(
            fingerprints["identity"].as_str().expect("identity"),
            fingerprints["userAgent"].as_str().expect("user agent")
        ),
        fingerprints["contextual"]
            .as_str()
            .expect("contextual fingerprint")
    );
}

#[test]
fn secret_envelopes_are_cross_language_compatible_and_authenticated() {
    let envelope = &vectors()["secretEnvelope"];
    let plaintext = envelope["plaintext"].as_str().expect("plaintext");
    let key = envelope["encryptionKey"].as_str().expect("encryption key");
    assert_eq!(
        decrypt_secret(envelope["envelope"].as_str().expect("envelope"), key)
            .expect("shared envelope decrypts"),
        plaintext
    );

    let encrypted = encrypt_secret(plaintext, key).expect("secret encrypts");
    assert_eq!(
        decrypt_secret(&encrypted, key).expect("secret decrypts"),
        plaintext
    );
    assert!(decrypt_secret(&encrypted, "wrong-key").is_err());
    assert!(decrypt_secret(&format!("{encrypted}:extra"), key).is_err());
}

#[test]
fn generated_credentials_have_the_requested_shapes() {
    let hex = generate_hex_token(32).expect("hex token");
    assert_eq!(hex.len(), 64);
    assert!(hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let base64url = generate_base64_url_token(32).expect("base64url token");
    assert_eq!(base64url.len(), 43);
    let generated = generate_opaque_token(32).expect("opaque token");
    assert_eq!(generated.digest, sha256_token_digest(&generated.plain));
    for digits in [4, 6, 8] {
        let code = generate_numeric_code(digits).expect("numeric code");
        assert_eq!(code.len(), digits as usize);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    }
}
