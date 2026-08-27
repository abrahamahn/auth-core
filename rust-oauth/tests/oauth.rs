use auth_oauth::{
    AppleProvider, AuthorizationOptions, GithubProvider, GoogleProvider, HttpMethod, KakaoProvider,
    OAuthErrorCode, OAuthProvider, OAuthStateEnvelope, TokenExchangeOptions, decode_oauth_state,
    encode_oauth_state, parse_token_response, pkce_pair_from_entropy,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey as EcSigningKey;
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sha2::Sha256;
use url::Url;

const NOW_MS: u64 = 1_718_452_800_000;

#[test]
fn google_builds_pkce_exchange_refresh_and_normalizes_identity() {
    let mut provider = GoogleProvider::new("google-client", "google-secret").unwrap();
    provider.force_consent = true;
    let options = AuthorizationOptions {
        code_challenge: Some("challenge".to_owned()),
        ..AuthorizationOptions::default()
    };
    let authorization = Url::parse(
        &provider
            .authorization_url("state", "https://app.example/callback", &options)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        authorization
            .query_pairs()
            .find(|(key, _)| key == "access_type")
            .map(|(_, value)| value.into_owned()),
        Some("offline".to_owned())
    );
    assert_eq!(
        authorization
            .query_pairs()
            .find(|(key, _)| key == "code_challenge_method")
            .map(|(_, value)| value.into_owned()),
        Some("S256".to_owned())
    );

    let exchange = provider.exchange_request(
        "code",
        "https://app.example/callback",
        &TokenExchangeOptions {
            code_verifier: Some("verifier".to_owned()),
        },
    );
    assert_eq!(exchange.method, HttpMethod::Post);
    assert!(exchange.body.unwrap().contains("code_verifier=verifier"));
    assert!(
        provider
            .refresh_request("refresh")
            .body
            .unwrap()
            .contains("client_secret=google-secret")
    );

    let tokens = parse_token_response(
        OAuthProvider::Google,
        200,
        r#"{"access_token":"access","refresh_token":"refresh","id_token":"id","token_type":"Bearer","expires_in":3600}"#,
        NOW_MS,
        false,
    )
    .unwrap();
    assert_eq!(tokens.id_token.as_deref(), Some("id"));
    assert_eq!(tokens.expires_at_ms, Some(NOW_MS + 3_600_000));

    let user = provider
        .parse_user_info(
            200,
            r#"{"sub":"google-user","email":"user@example.com","email_verified":true,"name":"Example User"}"#,
        )
        .unwrap();
    assert_eq!(user.id, "google-user");
    assert!(user.email_verified);
}

#[test]
fn provider_expiries_fail_closed_when_malformed_or_overflowing() {
    for body in [
        r#"{"access_token":"access","expires_in":-1}"#,
        r#"{"access_token":"access","expires_in":1.5}"#,
        r#"{"access_token":"access","expires_in":9007199254740991}"#,
    ] {
        assert_eq!(
            parse_token_response(OAuthProvider::Google, 200, body, NOW_MS, false)
                .unwrap_err()
                .code,
            OAuthErrorCode::TokenExchangeFailed
        );
    }

    assert_eq!(
        parse_token_response(
            OAuthProvider::Google,
            200,
            r#"{"access_token":"access","expires_in":1}"#,
            8_640_000_000_000_000,
            false,
        )
        .unwrap_err()
        .code,
        OAuthErrorCode::TokenExchangeFailed
    );
    assert_eq!(
        parse_token_response(
            OAuthProvider::Google,
            200,
            r#"{"access_token":"access"}"#,
            u64::MAX,
            false,
        )
        .unwrap_err()
        .code,
        OAuthErrorCode::InvalidConfig
    );
}

#[test]
fn github_and_kakao_select_verified_provider_identity() {
    let github = GithubProvider::new("client", "secret").unwrap();
    let user = github
        .parse_user_info(
            200,
            r#"{"id":42,"email":null,"name":"Octo Cat","avatar_url":"avatar"}"#,
            Some((
                200,
                r#"[{"email":"other@example.com","primary":false,"verified":true},{"email":"primary@example.com","primary":true,"verified":true}]"#,
            )),
        )
        .unwrap();
    assert_eq!(user.email, "primary@example.com");
    assert!(user.email_verified);
    let github_refresh: serde_json::Value =
        serde_json::from_str(&github.refresh_request("refresh").body.unwrap()).unwrap();
    assert_eq!(github_refresh["client_secret"], "secret");

    let kakao = KakaoProvider::new("client", Some("secret".to_owned())).unwrap();
    let user = kakao
        .parse_user_info(
            200,
            r#"{"id":123,"kakao_account":{"email":"kakao@example.com","is_email_verified":true,"profile":{"nickname":"Kakao User","profile_image_url":"picture"}}}"#,
        )
        .unwrap();
    assert_eq!(user.id, "123");
    assert_eq!(user.name.as_deref(), Some("Kakao User"));
    assert!(
        kakao
            .refresh_request("refresh")
            .body
            .unwrap()
            .contains("client_secret=secret")
    );
}

#[test]
fn apple_signs_client_assertions_and_verifies_rs256_identity_tokens() {
    let ec_key = EcSigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
    let ec_pem = ec_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let provider =
        AppleProvider::new("com.example.web", "TEAM123", "CLIENTKEY", ec_pem.as_str()).unwrap();
    let client_secret = provider.client_secret(NOW_MS / 1_000, 60).unwrap();
    let client_parts = client_secret.split('.').collect::<Vec<_>>();
    assert_eq!(client_parts.len(), 3);
    assert_eq!(URL_SAFE_NO_PAD.decode(client_parts[2]).unwrap().len(), 64);

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RS256",
            "kid": "apple-key"
        }))
        .unwrap(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": "https://appleid.apple.com",
            "aud": "com.example.web",
            "exp": NOW_MS / 1_000 + 3_600,
            "iat": NOW_MS / 1_000,
            "sub": "apple-user",
            "email": "apple@example.com",
            "email_verified": "true"
        }))
        .unwrap(),
    );
    let input = format!("{header}.{payload}");
    let signature = RsaSigningKey::<Sha256>::new(private_key).sign(input.as_bytes());
    let id_token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "apple-key",
            "use": "sig",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())
        }]
    })
    .to_string();

    let user = provider
        .verify_user_info(&id_token, 200, &jwks, NOW_MS / 1_000)
        .unwrap();
    assert_eq!(user.id, "apple-user");
    assert_eq!(user.email, "apple@example.com");
    assert!(user.email_verified);

    let mut signature_bytes = URL_SAFE_NO_PAD
        .decode(id_token.rsplit('.').next().unwrap())
        .unwrap();
    signature_bytes[0] ^= 1;
    let tampered = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature_bytes));
    assert_eq!(
        provider
            .verify_user_info(&tampered, 200, &jwks, NOW_MS / 1_000)
            .unwrap_err()
            .code,
        OAuthErrorCode::InvalidSignature
    );
}

#[test]
fn pkce_and_generic_state_match_the_typescript_wire_contract() {
    let pair = pkce_pair_from_entropy(&[7_u8; 32]);
    assert_eq!(pair.verifier.len(), 43);
    assert_eq!(
        pair.challenge,
        "3Ev4DHdHPRMPoN6GukAY_pi7IUAF5qWJHRK6kURvnoE"
    );

    let state = OAuthStateEnvelope {
        nonce: "nonce-123".to_owned(),
        provider: "google".to_owned(),
        redirect_uri: "https://app.example/callback".to_owned(),
        created_at_ms: NOW_MS,
        payload: json!({ "linking": true }),
    };
    let encoded =
        encode_oauth_state(&state, |value| Ok(URL_SAFE_NO_PAD.encode(value.as_bytes()))).unwrap();
    let decoded: OAuthStateEnvelope<serde_json::Value> =
        decode_oauth_state(&encoded, NOW_MS + 1_000, 10_000, |value| {
            Ok(String::from_utf8(URL_SAFE_NO_PAD.decode(value).unwrap()).unwrap())
        })
        .unwrap();
    assert_eq!(decoded, state);
    assert_eq!(
        decode_oauth_state::<serde_json::Value>(&encoded, NOW_MS + 10_001, 10_000, |value| {
            Ok(String::from_utf8(URL_SAFE_NO_PAD.decode(value).unwrap()).unwrap())
        })
        .unwrap_err()
        .code,
        OAuthErrorCode::StateExpired
    );
}
