//! Transport-neutral OAuth 2.0/OpenID Connect provider protocol and identity adapters.
//!
//! The crate owns provider request construction, response normalization, PKCE, generic state
//! envelopes, and Apple identity-token verification. Applications own HTTP execution, storage,
//! account linking, authorization policy, and user creation.

mod apple;
mod github;
mod google;
mod kakao;
mod state;
mod types;

pub use apple::AppleProvider;
pub use github::GithubProvider;
pub use google::GoogleProvider;
pub use kakao::KakaoProvider;
pub use state::{
    OAuthStateEnvelope, PkcePair, create_oauth_state, create_pkce_pair, decode_oauth_state,
    encode_oauth_state, pkce_pair_from_entropy,
};
pub use types::{
    AuthorizationOptions, HttpMethod, OAuthError, OAuthErrorCode, OAuthHttpRequest, OAuthProvider,
    OAuthTokenSet, OAuthUserInfo, TokenExchangeOptions, parse_token_response,
};
