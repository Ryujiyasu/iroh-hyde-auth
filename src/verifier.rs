//! The acceptor's side of institutional identity: deciding who is trusted.

use std::collections::HashMap;

use hyde::SigningAlgorithm;

/// A human-readable identifier for a verified institution (its roster label).
pub type InstitutionId = String;

/// Reasons an institutional assertion can be rejected.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The presented verifying key is not in the roster of trusted institutions.
    #[error("verifying key is not a trusted institution")]
    UntrustedKey,
    /// The signature did not verify against the presented key.
    #[error("signature verification failed")]
    BadSignature,
    /// The key is known but has been revoked.
    #[error("institution has been revoked")]
    Revoked,
    /// The underlying crypto verifier errored.
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Decides whether a presented institutional key + signature is trusted.
pub trait InstitutionVerifier: std::fmt::Debug + Send + Sync + 'static {
    /// Verify `signature` over `message` under `verifying_key`, **and** that the
    /// key belongs to a trusted, non-revoked institution. Returns the
    /// institution's identity on success.
    fn verify(
        &self,
        verifying_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<InstitutionId, VerifyError>;
}

/// The set of institutional verifying keys this acceptor trusts.
///
/// Maps each publishable ML-DSA verifying key to a human-readable label. For
/// the multi-institution threshold-FHE use case this is the known roster of
/// participating sites; remove a key to revoke it.
#[derive(Debug, Clone, Default)]
pub struct Roster {
    keys: HashMap<Vec<u8>, String>,
}

impl Roster {
    /// An empty roster (trusts no one).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted institution by its verifying key and a label.
    pub fn insert(&mut self, verifying_key: impl Into<Vec<u8>>, label: impl Into<String>) -> &mut Self {
        self.keys.insert(verifying_key.into(), label.into());
        self
    }

    /// Whether this key is currently trusted.
    pub fn contains(&self, verifying_key: &[u8]) -> bool {
        self.keys.contains_key(verifying_key)
    }

    /// The label for a trusted key, if present.
    pub fn label(&self, verifying_key: &[u8]) -> Option<&str> {
        self.keys.get(verifying_key).map(String::as_str)
    }

    /// Number of trusted institutions.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the roster is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// A [`InstitutionVerifier`] that checks an ML-DSA signature with hyde's
/// (TEE-free) verifier and then a [`Roster`] membership test.
#[derive(Debug, Clone)]
pub struct HydeVerifier {
    roster: Roster,
    algorithm: SigningAlgorithm,
}

impl HydeVerifier {
    /// Verify against the given roster using ML-DSA-65 (matches [`HydeSigner`]).
    ///
    /// [`HydeSigner`]: crate::HydeSigner
    pub fn new(roster: Roster) -> Self {
        Self {
            roster,
            algorithm: SigningAlgorithm::MlDsa65,
        }
    }

    /// Override the ML-DSA parameter set (must match the signer).
    pub fn with_algorithm(mut self, algorithm: SigningAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

impl InstitutionVerifier for HydeVerifier {
    fn verify(
        &self,
        verifying_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<InstitutionId, VerifyError> {
        // Roster membership first — cheap, and avoids spending crypto on
        // unknown keys.
        if !self.roster.contains(verifying_key) {
            return Err(VerifyError::UntrustedKey);
        }
        let ok = hyde::verify_signature(self.algorithm, verifying_key, message, signature)
            .map_err(|e| VerifyError::Crypto(e.to_string()))?;
        if !ok {
            return Err(VerifyError::BadSignature);
        }
        Ok(self
            .roster
            .label(verifying_key)
            .unwrap_or_default()
            .to_string())
    }
}
