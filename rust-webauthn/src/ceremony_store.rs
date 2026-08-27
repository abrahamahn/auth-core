use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebauthnCeremonyKind {
    Registration,
    Authentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebauthnCeremony<State> {
    pub kind: WebauthnCeremonyKind,
    pub state: State,
    pub expires_at_ms: u64,
    pub subject_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebauthnCeremonyStoreError {
    InvalidTtl,
    EmptyKey,
    ExpiryOverflow,
    Missing,
    Expired,
    KindMismatch,
}

impl Display for WebauthnCeremonyStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTtl => "ceremony TTL must be positive",
            Self::EmptyKey => "ceremony key must not be empty",
            Self::ExpiryOverflow => "ceremony expiry overflowed u64",
            Self::Missing => "WebAuthn ceremony was not found",
            Self::Expired => "WebAuthn ceremony has expired",
            Self::KindMismatch => "WebAuthn ceremony kind does not match",
        })
    }
}

impl Error for WebauthnCeremonyStoreError {}

/// Single-process, single-use ceremony-state storage for tests and simple deployments.
///
/// Distributed applications must use an atomic shared store with equivalent consume-before-verify
/// semantics. Every consume attempt removes the entry before expiry and kind checks, so even a
/// failed verification cannot replay the state.
#[derive(Clone, Debug)]
pub struct InMemoryWebauthnCeremonyStore<State> {
    ttl_ms: u64,
    entries: HashMap<String, WebauthnCeremony<State>>,
}

impl<State> InMemoryWebauthnCeremonyStore<State> {
    /// Creates an empty ceremony store with a fixed positive TTL.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnCeremonyStoreError::InvalidTtl`] when `ttl_ms` is zero.
    pub fn new(ttl_ms: u64) -> Result<Self, WebauthnCeremonyStoreError> {
        if ttl_ms == 0 {
            return Err(WebauthnCeremonyStoreError::InvalidTtl);
        }
        Ok(Self {
            ttl_ms,
            entries: HashMap::new(),
        })
    }

    /// Stores opaque server-side ceremony state until its checked expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty key or timestamp overflow.
    pub fn put(
        &mut self,
        key: impl Into<String>,
        kind: WebauthnCeremonyKind,
        state: State,
        subject_id: Option<String>,
        now_ms: u64,
    ) -> Result<(), WebauthnCeremonyStoreError> {
        let key = key.into();
        if key.is_empty() {
            return Err(WebauthnCeremonyStoreError::EmptyKey);
        }
        self.prune(now_ms);
        let expires_at_ms = now_ms
            .checked_add(self.ttl_ms)
            .ok_or(WebauthnCeremonyStoreError::ExpiryOverflow)?;
        self.entries.insert(
            key,
            WebauthnCeremony {
                kind,
                state,
                expires_at_ms,
                subject_id,
            },
        );
        Ok(())
    }

    /// Atomically removes and returns a matching, unexpired ceremony.
    ///
    /// The entry is removed before validation so missing, expired, mismatched, and subsequently
    /// failed cryptographic verification attempts are all single-use.
    ///
    /// # Errors
    ///
    /// Returns a stable missing, expired, or kind-mismatch category.
    pub fn consume(
        &mut self,
        key: &str,
        expected_kind: WebauthnCeremonyKind,
        now_ms: u64,
    ) -> Result<WebauthnCeremony<State>, WebauthnCeremonyStoreError> {
        let ceremony = self
            .entries
            .remove(key)
            .ok_or(WebauthnCeremonyStoreError::Missing)?;
        if ceremony.expires_at_ms <= now_ms {
            return Err(WebauthnCeremonyStoreError::Expired);
        }
        if ceremony.kind != expected_kind {
            return Err(WebauthnCeremonyStoreError::KindMismatch);
        }
        Ok(ceremony)
    }

    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, ceremony| ceremony.expires_at_ms > now_ms);
        before - self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
