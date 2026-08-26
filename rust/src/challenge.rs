use std::collections::HashMap;
use std::hash::Hash;

use crate::{AuthError, AuthResult};

#[derive(Clone, Debug)]
pub struct ExpiringReplayGuard<Key> {
    expires_at_by_key: HashMap<Key, u64>,
}

impl<Key> Default for ExpiringReplayGuard<Key> {
    fn default() -> Self {
        Self {
            expires_at_by_key: HashMap::new(),
        }
    }
}

impl<Key: Eq + Hash> ExpiringReplayGuard<Key> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks a key as consumed until its calculated expiry.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ArithmeticOverflow`] if the deadline exceeds [`u64::MAX`].
    pub fn burn(&mut self, key: Key, ttl_ms: u64, now_ms: u64) -> AuthResult<()> {
        self.sweep(now_ms);
        if ttl_ms == 0 {
            self.expires_at_by_key.remove(&key);
            return Ok(());
        }
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .ok_or(AuthError::ArithmeticOverflow("challenge expiry overflow"))?;
        self.expires_at_by_key.insert(key, expires_at_ms);
        Ok(())
    }

    pub fn is_burned(&mut self, key: &Key, now_ms: u64) -> bool {
        let Some(expires_at_ms) = self.expires_at_by_key.get(key).copied() else {
            return false;
        };
        if expires_at_ms <= now_ms {
            self.expires_at_by_key.remove(key);
            return false;
        }
        true
    }

    pub fn clear(&mut self) {
        self.expires_at_by_key.clear();
    }

    #[must_use]
    pub fn len(&mut self, now_ms: u64) -> usize {
        self.sweep(now_ms);
        self.expires_at_by_key.len()
    }

    #[must_use]
    pub fn is_empty(&mut self, now_ms: u64) -> bool {
        self.len(now_ms) == 0
    }

    fn sweep(&mut self, now_ms: u64) {
        self.expires_at_by_key
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
    }
}
