//! Argon2 password-hashing adapter for Auth Core.

use std::fmt;
use std::sync::{Mutex, MutexGuard};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2 algorithm variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Argon2Variant {
    Argon2d,
    Argon2i,
    Argon2id,
}

/// Resource parameters used for new password hashes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2Config {
    /// Memory cost in KiB.
    pub memory_cost: u32,
    /// Number of iterations.
    pub time_cost: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Algorithm variant.
    pub variant: Argon2Variant,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 19_456,
            time_cost: 2,
            parallelism: 1,
            variant: Argon2Variant::Argon2id,
        }
    }
}

/// Adapter failures. Password mismatches are returned as `Ok(false)`, not errors.
#[derive(Debug, Eq, PartialEq)]
pub enum PasswordAdapterError {
    InvalidConfig(String),
    Hash(String),
    Entropy(String),
    PoolPoisoned,
}

impl fmt::Display for PasswordAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid Argon2 config: {message}"),
            Self::Hash(message) => write!(formatter, "password hashing failed: {message}"),
            Self::Entropy(message) => write!(formatter, "secure entropy failed: {message}"),
            Self::PoolPoisoned => formatter.write_str("dummy hash pool lock was poisoned"),
        }
    }
}

impl std::error::Error for PasswordAdapterError {}

fn algorithm(variant: Argon2Variant) -> Algorithm {
    match variant {
        Argon2Variant::Argon2d => Algorithm::Argon2d,
        Argon2Variant::Argon2i => Algorithm::Argon2i,
        Argon2Variant::Argon2id => Algorithm::Argon2id,
    }
}

fn algorithm_name(variant: Argon2Variant) -> &'static str {
    match variant {
        Argon2Variant::Argon2d => "argon2d",
        Argon2Variant::Argon2i => "argon2i",
        Argon2Variant::Argon2id => "argon2id",
    }
}

fn engine(config: Argon2Config) -> Result<Argon2<'static>, PasswordAdapterError> {
    let params = Params::new(
        config.memory_cost,
        config.time_cost,
        config.parallelism,
        None,
    )
    .map_err(|error| PasswordAdapterError::InvalidConfig(error.to_string()))?;
    Ok(Argon2::new(
        algorithm(config.variant),
        Version::V0x13,
        params,
    ))
}

fn random_salt() -> Result<SaltString, PasswordAdapterError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| PasswordAdapterError::Entropy(error.to_string()))?;
    SaltString::encode_b64(&bytes).map_err(|error| PasswordAdapterError::Hash(error.to_string()))
}

/// Hash a password into a self-describing Argon2 PHC string.
///
/// # Errors
///
/// Returns an error when the resource configuration is invalid, secure entropy is unavailable,
/// or the underlying Argon2 implementation rejects the operation.
pub fn hash_password(password: &str, config: Argon2Config) -> Result<String, PasswordAdapterError> {
    engine(config)?
        .hash_password(password.as_bytes(), &random_salt()?)
        .map(|hash| hash.to_string())
        .map_err(|error| PasswordAdapterError::Hash(error.to_string()))
}

/// Verify a password. Malformed PHC strings and password mismatches both return `false`.
#[must_use]
pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Determine whether a PHC string should be replaced with the configured parameters.
#[must_use]
pub fn needs_rehash(encoded_hash: &str, config: Argon2Config) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return true;
    };
    if engine(config).is_err() {
        return true;
    }

    parsed.algorithm.as_str() != algorithm_name(config.variant)
        || parsed.version != Some(19)
        || parsed.params.get_decimal("m") != Some(config.memory_cost)
        || parsed.params.get_decimal("t") != Some(config.time_cost)
        || parsed.params.get_decimal("p") != Some(config.parallelism)
}

/// Per-application dummy hashes used to equalize unknown-account verification.
pub struct DummyHashPool {
    config: Argon2Config,
    size: usize,
    hashes: Mutex<Vec<String>>,
}

impl DummyHashPool {
    /// Create an empty pool. Call [`Self::initialize`] during application startup.
    ///
    /// # Errors
    ///
    /// Returns an error when `size` is zero or the Argon2 configuration is invalid.
    pub fn new(config: Argon2Config, size: usize) -> Result<Self, PasswordAdapterError> {
        if size == 0 {
            return Err(PasswordAdapterError::InvalidConfig(
                "dummy hash pool size must be positive".to_owned(),
            ));
        }
        engine(config)?;
        Ok(Self {
            config,
            size,
            hashes: Mutex::new(Vec::new()),
        })
    }

    fn hashes(&self) -> Result<MutexGuard<'_, Vec<String>>, PasswordAdapterError> {
        self.hashes
            .lock()
            .map_err(|_| PasswordAdapterError::PoolPoisoned)
    }

    /// Populate the pool once. Repeated calls are idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool lock is poisoned, entropy is unavailable, or hashing fails.
    pub fn initialize(&self) -> Result<(), PasswordAdapterError> {
        let mut hashes = self.hashes()?;
        if hashes.len() == self.size {
            return Ok(());
        }

        let mut generated = Vec::with_capacity(self.size);
        for index in 0..self.size {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce)
                .map_err(|error| PasswordAdapterError::Entropy(error.to_string()))?;
            generated.push(hash_password(
                &format!("auth-core-dummy-{index}-{}", hex(&nonce)),
                self.config,
            )?);
        }
        *hashes = generated;
        Ok(())
    }

    /// Report whether the complete pool is ready.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool lock is poisoned.
    pub fn is_initialized(&self) -> Result<bool, PasswordAdapterError> {
        Ok(self.hashes()?.len() == self.size)
    }

    /// Discard all pre-computed hashes.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool lock is poisoned.
    pub fn reset(&self) -> Result<(), PasswordAdapterError> {
        self.hashes()?.clear();
        Ok(())
    }

    fn fallback_hash(&self) -> Result<String, PasswordAdapterError> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| PasswordAdapterError::Entropy(error.to_string()))?;
        hash_password(&format!("auth-core-fallback-{}", hex(&nonce)), self.config)
    }

    fn random_hash(&self) -> Result<String, PasswordAdapterError> {
        let hashes = self.hashes()?;
        if hashes.is_empty() {
            drop(hashes);
            return self.fallback_hash();
        }

        let mut random = [0_u8; 8];
        getrandom::fill(&mut random)
            .map_err(|error| PasswordAdapterError::Entropy(error.to_string()))?;
        #[allow(clippy::cast_possible_truncation)]
        let index = (u64::from_le_bytes(random) % hashes.len() as u64) as usize;
        Ok(hashes[index].clone())
    }

    /// Always perform Argon2 verification, including when `encoded_hash` is absent.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool lock is poisoned or a fallback dummy hash cannot be created.
    pub fn verify(
        &self,
        password: &str,
        encoded_hash: Option<&str>,
    ) -> Result<bool, PasswordAdapterError> {
        let present_hash = encoded_hash.filter(|hash| !hash.is_empty());
        let hash = match present_hash {
            Some(hash) => hash.to_owned(),
            None => self.random_hash()?,
        };
        let valid = verify_password(password, &hash);
        Ok(present_hash.is_some() && valid)
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
