use serde_json::Value;

use crate::types::{
    AuthorizationOptions, OAuthError, OAuthErrorCode, OAuthHttpRequest, OAuthProvider,
    OAuthUserInfo, TokenExchangeOptions, append_authorization_options, authorization_url, boolish,
    optional_string, required_config, required_id, required_string, response_object, string_vec,
};

const KAKAO_AUTH_URL: &str = "https://kauth.kakao.com/oauth/authorize";
const KAKAO_TOKEN_URL: &str = "https://kauth.kakao.com/oauth/token";
const KAKAO_USERINFO_URL: &str = "https://kapi.kakao.com/v2/user/me";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KakaoProvider {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
}

impl KakaoProvider {
    /// # Errors
    /// Returns [`OAuthErrorCode::InvalidConfig`] for an empty client ID.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            client_id: required_config(client_id.into(), "client_id", OAuthProvider::Kakao)?,
            client_secret: client_secret.filter(|secret| !secret.trim().is_empty()),
            scopes: string_vec(&["account_email", "profile_nickname", "profile_image"]),
        })
    }

    /// # Errors
    /// Returns an error only if the static provider URL cannot be parsed.
    pub fn authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
        options: &AuthorizationOptions,
    ) -> Result<String, OAuthError> {
        let scopes = self.scopes.join(",");
        let mut url = authorization_url(
            KAKAO_AUTH_URL,
            &[
                ("client_id", &self.client_id),
                ("redirect_uri", redirect_uri),
                ("response_type", "code"),
                ("scope", &scopes),
                ("state", state),
            ],
            OAuthProvider::Kakao,
        )?;
        append_authorization_options(&mut url.query_pairs_mut(), options, "login_hint");
        Ok(url.into())
    }

    #[must_use]
    pub fn exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        options: &TokenExchangeOptions,
    ) -> OAuthHttpRequest {
        self.token_request(
            &[
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
                ("code", code),
            ],
            options.code_verifier.as_deref(),
        )
    }

    #[must_use]
    pub fn refresh_request(&self, refresh_token: &str) -> OAuthHttpRequest {
        self.token_request(
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
            None,
        )
    }

    fn token_request(&self, values: &[(&str, &str)], verifier: Option<&str>) -> OAuthHttpRequest {
        let mut fields = values.to_vec();
        fields.push(("client_id", &self.client_id));
        if let Some(secret) = &self.client_secret {
            fields.push(("client_secret", secret));
        }
        if let Some(verifier) = verifier {
            fields.push(("code_verifier", verifier));
        }
        OAuthHttpRequest::form_post(KAKAO_TOKEN_URL, &fields)
    }

    #[must_use]
    pub fn user_info_request(&self, access_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::get(KAKAO_USERINFO_URL, Some(access_token))
    }

    /// # Errors
    /// Returns a categorized provider response error or [`OAuthErrorCode::NoEmail`].
    pub fn parse_user_info(&self, status: u16, body: &str) -> Result<OAuthUserInfo, OAuthError> {
        let data = response_object(
            status,
            body,
            OAuthProvider::Kakao,
            OAuthErrorCode::UserInfoFailed,
        )?;
        let account = data
            .get("kakao_account")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OAuthError::provider(
                    OAuthProvider::Kakao,
                    OAuthErrorCode::NoEmail,
                    "No email found on Kakao account",
                )
            })?;
        let email = required_string(
            account,
            "email",
            OAuthProvider::Kakao,
            OAuthErrorCode::NoEmail,
        )?;
        let profile = account.get("profile").and_then(Value::as_object);
        let id = required_id(&data, OAuthProvider::Kakao, "Kakao response is missing id")?;
        Ok(OAuthUserInfo {
            id,
            email,
            name: profile.and_then(|value| optional_string(value, "nickname")),
            email_verified: boolish(account.get("is_email_verified")),
            picture: profile.and_then(|value| optional_string(value, "profile_image_url")),
        })
    }
}
