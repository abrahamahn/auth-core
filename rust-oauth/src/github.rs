use serde_json::{Value, json};

use crate::types::{
    AuthorizationOptions, OAuthError, OAuthErrorCode, OAuthHttpRequest, OAuthProvider,
    OAuthUserInfo, TokenExchangeOptions, append_authorization_options, authorization_url,
    optional_string, required_config, required_id, response_json, response_object, string_vec,
    success,
};

const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USERINFO_URL: &str = "https://api.github.com/user";
const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProvider {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub allow_signup: bool,
}

impl GithubProvider {
    /// # Errors
    /// Returns [`OAuthErrorCode::InvalidConfig`] for empty credentials.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            client_id: required_config(client_id.into(), "client_id", OAuthProvider::Github)?,
            client_secret: required_config(
                client_secret.into(),
                "client_secret",
                OAuthProvider::Github,
            )?,
            scopes: string_vec(&["user:email", "read:user"]),
            allow_signup: true,
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
        let scopes = self.scopes.join(" ");
        let allow_signup = self.allow_signup.to_string();
        let mut url = authorization_url(
            GITHUB_AUTH_URL,
            &[
                ("client_id", &self.client_id),
                ("redirect_uri", redirect_uri),
                ("scope", &scopes),
                ("state", state),
                ("allow_signup", &allow_signup),
            ],
            OAuthProvider::Github,
        )?;
        append_authorization_options(&mut url.query_pairs_mut(), options, "login");
        Ok(url.into())
    }

    #[must_use]
    pub fn exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        options: &TokenExchangeOptions,
    ) -> OAuthHttpRequest {
        let mut body = json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        });
        if let (Some(object), Some(verifier)) = (body.as_object_mut(), &options.code_verifier) {
            object.insert("code_verifier".to_owned(), Value::String(verifier.clone()));
        }
        OAuthHttpRequest::json_post(GITHUB_TOKEN_URL, &body)
    }

    #[must_use]
    pub fn user_info_requests(&self, access_token: &str) -> [OAuthHttpRequest; 2] {
        let mut profile = OAuthHttpRequest::get(GITHUB_USERINFO_URL, Some(access_token));
        let mut emails = OAuthHttpRequest::get(GITHUB_EMAILS_URL, Some(access_token));
        for request in [&mut profile, &mut emails] {
            request.headers.insert(
                "Accept".to_owned(),
                "application/vnd.github+json".to_owned(),
            );
            request
                .headers
                .insert("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned());
        }
        [profile, emails]
    }

    #[must_use]
    pub fn refresh_request(&self, refresh_token: &str) -> OAuthHttpRequest {
        OAuthHttpRequest::json_post(
            GITHUB_TOKEN_URL,
            &json!({
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }),
        )
    }

    /// Normalize the profile and optional email-list responses.
    ///
    /// # Errors
    /// Returns a categorized provider response error or [`OAuthErrorCode::NoEmail`].
    pub fn parse_user_info(
        &self,
        profile_status: u16,
        profile_body: &str,
        emails_response: Option<(u16, &str)>,
    ) -> Result<OAuthUserInfo, OAuthError> {
        let profile = response_object(
            profile_status,
            profile_body,
            OAuthProvider::Github,
            OAuthErrorCode::UserInfoFailed,
        )?;
        let mut email = optional_string(&profile, "email");
        let mut email_verified = false;
        if let Some((status, body)) = emails_response.filter(|(status, _)| success(*status)) {
            let emails = response_json(
                status,
                body,
                OAuthProvider::Github,
                OAuthErrorCode::UserInfoFailed,
            )?;
            if let Some(items) = emails.as_array() {
                let verified = items
                    .iter()
                    .filter_map(Value::as_object)
                    .find(|entry| {
                        entry.get("primary").and_then(Value::as_bool) == Some(true)
                            && entry.get("verified").and_then(Value::as_bool) == Some(true)
                    })
                    .or_else(|| {
                        items.iter().filter_map(Value::as_object).find(|entry| {
                            entry.get("verified").and_then(Value::as_bool) == Some(true)
                        })
                    });
                if let Some(selected) = verified.and_then(|entry| optional_string(entry, "email")) {
                    email = Some(selected);
                    email_verified = true;
                }
            }
        }
        let email = email.ok_or_else(|| {
            OAuthError::provider(
                OAuthProvider::Github,
                OAuthErrorCode::NoEmail,
                "No email found on GitHub account",
            )
        })?;
        let id = required_id(
            &profile,
            OAuthProvider::Github,
            "GitHub response is missing id",
        )?;
        Ok(OAuthUserInfo {
            id,
            email,
            name: optional_string(&profile, "name"),
            email_verified,
            picture: optional_string(&profile, "avatar_url"),
        })
    }
}
