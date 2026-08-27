use auth_crypto::{
    CsrfValidationOptions, contextual_device_fingerprint, decrypt_csrf_token, decrypt_secret,
    encrypt_csrf_token, encrypt_secret, generate_base64_url_token, generate_csrf_token,
    generate_hex_token, generate_numeric_code, generate_opaque_token, sha256_token_digest,
    sign_csrf_token, stable_device_fingerprint, validate_csrf_token, verify_signed_csrf_token,
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

#[test]
fn csrf_tokens_match_typescript_and_reject_tampering() {
    let vectors = vectors();
    let csrf = &vectors["csrf"];
    let token = csrf["token"].as_str().expect("csrf token");
    let secret = csrf["secret"].as_str().expect("csrf secret");
    let signed = csrf["signedToken"].as_str().expect("signed csrf token");
    let encrypted = csrf["encryptedToken"]
        .as_str()
        .expect("encrypted csrf token");

    assert_eq!(sign_csrf_token(token, secret).expect("token signs"), signed);
    assert_eq!(
        verify_signed_csrf_token(signed, secret).expect("signature verifies"),
        Some(token.to_owned())
    );
    assert_eq!(
        decrypt_csrf_token(encrypted, secret).expect("envelope decrypts"),
        Some(signed.to_owned())
    );
    assert!(
        decrypt_csrf_token(&format!("{encrypted}x"), secret)
            .expect("tampered envelope is handled")
            .is_none()
    );
}

#[test]
fn csrf_tokens_round_trip_and_validate_double_submit_pairs() {
    let secret = "round-trip-csrf-secret";
    let token = generate_csrf_token().expect("csrf token generates");
    let signed = sign_csrf_token(&token, secret).expect("csrf token signs");
    let cookie = encrypt_csrf_token(&signed, secret).expect("csrf token encrypts");
    let options = CsrfValidationOptions {
        encrypted: true,
        signed: true,
    };
    assert!(
        validate_csrf_token(Some(&cookie), Some(&token), secret, options)
            .expect("matching pair validates")
    );
    assert!(
        !validate_csrf_token(Some(&cookie), Some("wrong"), secret, options)
            .expect("mismatch is rejected")
    );
    assert!(validate_csrf_token(None, Some(&token), secret, options).is_ok_and(|valid| !valid));
    assert!(sign_csrf_token(&token, "").is_err());
}
