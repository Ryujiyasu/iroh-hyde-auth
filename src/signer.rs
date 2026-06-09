//! The initiator's side of institutional identity: producing signatures.

use std::sync::{Arc, Mutex};

use hyde::{FallbackPolicy, HydeContext, SigningAlgorithm, WrappedSigningKey};

use crate::error::{Error, Result};

/// Run an [`InstitutionalSigner::sign`] on the blocking thread pool.
///
/// A hardware signature (TPM ~10–100 ms) would otherwise stall the async
/// worker that drives the connection. Callers on the connection path use this.
pub(crate) async fn sign_blocking(
    signer: &Arc<dyn InstitutionalSigner>,
    message: &[u8],
) -> Result<Vec<u8>> {
    let signer = signer.clone();
    let message = message.to_vec();
    tokio::task::spawn_blocking(move || signer.sign(&message))
        .await
        .map_err(|e| Error::Signer(format!("signing task failed: {e}")))?
}

/// Produces institutional signatures over auth transcripts.
///
/// This is the abstraction point for the signing backend. The shipped
/// implementation is [`HydeSigner`] (TPM-bound ML-DSA via the `hyde` crate); a
/// second backend (e.g. `ssh-agent`) can implement the same trait to validate
/// portability.
pub trait InstitutionalSigner: std::fmt::Debug + Send + Sync + 'static {
    /// The institution's publishable verifying key. Distribute this to peers
    /// out of band so they can add it to their [`crate::Roster`].
    fn verifying_key(&self) -> Vec<u8>;

    /// Sign the auth transcript. May be slow (a TPM signature is ~10–100 ms),
    /// so callers run this off the connection hot path.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// A [`InstitutionalSigner`] backed by a hyde TEE context.
///
/// The ML-DSA signing seed is sealed by the active TEE backend's Primary Key;
/// the verifying key is held in the clear and published to peers.
pub struct HydeSigner {
    inner: Mutex<Inner>,
    verifying_key: Vec<u8>,
}

struct Inner {
    ctx: HydeContext,
    key: WrappedSigningKey,
}

impl HydeSigner {
    /// Generate a fresh device-bound institutional identity.
    ///
    /// `fallback` controls what happens when no TEE hardware is present. For a
    /// real institutional identity pass [`FallbackPolicy::Deny`] — silently
    /// falling back to a software key would defeat the hardware-binding the
    /// whole design depends on. [`FallbackPolicy::Software`] is for tests only.
    pub fn generate(fallback: FallbackPolicy) -> Result<Self> {
        let mut ctx = hyde::auto_detect(fallback).map_err(|e| Error::Signer(e.to_string()))?;
        let key = ctx
            .generate_signing_key(SigningAlgorithm::MlDsa65)
            .map_err(|e| Error::Signer(e.to_string()))?;
        Ok(Self::from_parts(ctx, key))
    }

    /// Reconstruct a signer from a persisted [`WrappedSigningKey`] and a hyde
    /// context bound to the *same* TEE backend that produced it.
    pub fn from_parts(ctx: HydeContext, key: WrappedSigningKey) -> Self {
        let verifying_key = key.verifying_key.clone();
        Self {
            inner: Mutex::new(Inner { ctx, key }),
            verifying_key,
        }
    }
}

impl std::fmt::Debug for HydeSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HydeSigner")
            .field("verifying_key_len", &self.verifying_key.len())
            .finish_non_exhaustive()
    }
}

impl InstitutionalSigner for HydeSigner {
    fn verifying_key(&self) -> Vec<u8> {
        self.verifying_key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::Signer("signer mutex poisoned".into()))?;
        let inner = &mut *guard;
        inner
            .ctx
            .sign(&inner.key, message)
            .map_err(|e| Error::Signer(e.to_string()))
    }
}
