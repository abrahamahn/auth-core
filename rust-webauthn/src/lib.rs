//! Rust `WebAuthn` relying-party adapter for Auth Core.
//!
//! Browser challenge responses and ceremony state use `webauthn-rs`'s audited, serializable types.
//! Applications must persist the returned registration/authentication state server-side, consume
//! it exactly once, associate passkeys with their own principals, and persist passkey updates after
//! authentication. Ceremony-state serialization is enabled solely for server-side shared storage;
//! these values must never be returned to or stored by the client.

use std::time::Duration;

mod ceremony_store;

pub use ceremony_store::{
    InMemoryWebauthnCeremonyStore, WebauthnCeremony, WebauthnCeremonyKind,
    WebauthnCeremonyStoreError,
};

pub use url::Url;
pub use uuid::Uuid;
pub use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, WebauthnError, WebauthnResult,
};
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

#[derive(Clone, Copy, Debug)]
pub struct AuthWebauthnConfig<'a> {
    pub rp_name: &'a str,
    pub rp_id: &'a str,
    pub rp_origin: &'a Url,
    pub timeout: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct AuthWebauthnServer {
    inner: Webauthn,
}

impl AuthWebauthnServer {
    /// Constructs a relying-party verifier and validates that the RP ID belongs to the origin.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnError`] when the relying-party configuration is invalid.
    pub fn new(config: AuthWebauthnConfig<'_>) -> WebauthnResult<Self> {
        let builder = WebauthnBuilder::new(config.rp_id, config.rp_origin)?.rp_name(config.rp_name);
        let builder = match config.timeout {
            Some(timeout) => builder.timeout(timeout),
            None => builder,
        };
        Ok(Self {
            inner: builder.build()?,
        })
    }

    /// Starts a passkey registration ceremony.
    ///
    /// The returned [`PasskeyRegistration`] MUST be stored server-side and consumed only once by
    /// [`Self::finish_registration`]. Human-readable names are presentation data, not identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnError`] when registration options cannot be generated.
    pub fn start_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
        self.inner.start_passkey_registration(
            user_id,
            user_name,
            user_display_name,
            exclude_credentials,
        )
    }

    /// Finishes a registration ceremony and returns the passkey that the application must persist.
    ///
    /// Applications MUST additionally enforce global credential-ID uniqueness before associating
    /// the passkey with a principal.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnError`] when the response fails origin, RP ID, challenge, attestation, user
    /// presence, or user-verification checks.
    pub fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> WebauthnResult<Passkey> {
        self.inner.finish_passkey_registration(response, state)
    }

    /// Starts authentication against the supplied passkeys.
    ///
    /// The returned [`PasskeyAuthentication`] MUST be stored server-side and consumed only once by
    /// [`Self::finish_authentication`].
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnError`] when authentication options cannot be generated.
    pub fn start_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        self.inner.start_passkey_authentication(passkeys)
    }

    /// Verifies an authentication assertion against its server-side ceremony state.
    ///
    /// The caller MUST pass the result to [`update_passkey`] and persist a changed passkey.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnError`] when the assertion fails challenge, signature, origin, RP ID,
    /// counter, user-presence, or user-verification checks.
    pub fn finish_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.inner.finish_passkey_authentication(response, state)
    }

    #[must_use]
    pub fn allowed_origins(&self) -> &[Url] {
        self.inner.get_allowed_origins()
    }
}

/// Applies counter and backup-state changes after successful authentication.
///
/// Returns `None` if the result belongs to another credential, `Some(false)` if no persistence
/// update is needed, and `Some(true)` when the modified passkey MUST be persisted.
pub fn update_passkey(passkey: &mut Passkey, result: &AuthenticationResult) -> Option<bool> {
    passkey.update_credential(result)
}
