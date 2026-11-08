use crate::types::{
    AuthorizationOptions, OAuthError, OAuthErrorCode, OAuthHttpRequest, OAuthProvider,
    OAuthUserInfo, TokenExchangeOptions, append_authorization_options, authorization_url, boolish,
    optional_string, required_config, required_string, response_object, string_vec,
};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleProvider {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub request_offline_access: bool,
    pub force_consent: bool,
}

impl GoogleProvider {
    /// Construct the provider with identity-only default scopes.
    ///
    /// # Errors
    /// Returns [`OAuthErrorCode::InvalidConfig`] for empty credentials.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        let client_id = required_config(client_id.into(), "client_id", OAuthProvider::Google)?;
        let client_secret =
            required_config(client_secret.into(), "client_secret", OAuthProvider::Google)?;
        Ok(Self {
            client_id,
            client_secret,
            scopes: string_vec(&["openid", "email", "profile"]),
            request_offline_access: true,
            force_consent: false,
        })
    }

    /// Build the browser authorization URL.
    ///
    /// # Errors
    /// Returns an error only if the static provider URL cannot be parsed.
    pub fn authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
        options: &AuthorizationOptions,
    ) -> Result<String, OAuthError> {
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", ""),
            ("state", state),
        ];
        let scopes = self.scopes.join(" ");
        fields[3].1 = &scopes;
        let mut url = authorization_url(GOOGLE_AUTH_URL, &fields, OAuthProvider::Google)?;
        {
            let mut query = url.query_pairs_mut();
            if self.request_offline_access {
                query.append_pair("access_type", "offline");
            }
            if self.force_consent {
                query.append_pair("prompt", "consent");
            }
            append_authorization_options(&mut query, options, "login_hint");
        }
        Ok(url.into())
    }

    #[must_use]
    pub fn exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        options: &TokenExchangeOptions,
    ) -> OAuthHttpRequest {
        let mut fields = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(verifier) = &options.code_verifier {
            fields.push(("code_verifier", verifier));
        }
        OAuthHttpRequest::form_post(GOOGLE_TOKEN_URL, &fields)
    }

    #[must_use]
    pub fn user_info_request(&self, access_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::get(GOOGLE_USERINFO_URL, Some(access_token))
    }

    #[must_use]
    pub fn refresh_request(&self, refresh_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::form_post(
            GOOGLE_TOKEN_URL,
            &[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        )
    }

    /// Parse and normalize Google `UserInfo` JSON.
    ///
    /// # Errors
    /// Returns a categorized provider response error.
    pub fn parse_user_info(&self, status: u16, body: &str) -> Result<OAuthUserInfo, OAuthError> {
        let data = response_object(
            status,
            body,
            OAuthProvider::Google,
            OAuthErrorCode::UserInfoFailed,
        )?;
        let email = required_string(
            &data,
            "email",
            OAuthProvider::Google,
            OAuthErrorCode::NoEmail,
        )?;
        Ok(OAuthUserInfo {
            id: required_string(
                &data,
                "sub",
                OAuthProvider::Google,
                OAuthErrorCode::UserInfoFailed,
            )?,
            email,
            name: optional_string(&data, "name"),
            email_verified: boolish(data.get("email_verified")),
            picture: optional_string(&data, "picture"),
        })
    }
}
