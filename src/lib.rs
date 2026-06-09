//! Institutional, hardware-bound authentication for [iroh] connections.
//!
//! `iroh-hyde-auth` puts a mutually-authenticated, TPM-bound *institutional*
//! identity in front of ordinary iroh protocols **without those protocols
//! needing any awareness of it**. It follows the structure of iroh's
//! [`auth-hook`] example, but replaces the example's shared secret token with a
//! challenge–response signed by [hyde] (ML-DSA / FIPS 204, with the signing
//! seed sealed to a TPM).
//!
//! # Two identities
//!
//! * **Transport identity** — the endpoint's ordinary in-memory ephemeral
//!   `SecretKey`. Fast handshakes, free to rotate.
//! * **Institutional identity** — a TPM-bound ML-DSA key. Exchanged over a
//!   *separate* auth ALPN ([`ALPN`]) and bound to the ephemeral transport id, so
//!   a stolen on-disk key or a relay cannot impersonate an institution.
//!
//! # Wiring
//!
//! Acceptor:
//! ```ignore
//! let verifier = Arc::new(HydeVerifier::new(roster));
//! let (hook, auth_protocol) = incoming(verifier);
//! let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
//! let router = Router::builder(endpoint)
//!     .accept(iroh_hyde_auth::ALPN, auth_protocol)
//!     .accept(b"my-app/0", my_protocol)
//!     .spawn();
//! ```
//!
//! Initiator:
//! ```ignore
//! let signer = Arc::new(HydeSigner::generate(FallbackPolicy::Deny)?);
//! let (hook, task) = outgoing(signer);
//! let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
//! let _guard = task.spawn(endpoint.clone());
//! // Any non-auth connection now authenticates transparently first.
//! ```
//!
//! See `examples/echo-auth.rs` for a complete, compile-checked end-to-end run.
//!
//! [iroh]: https://docs.rs/iroh
//! [hyde]: https://gitlab.com/Ryujiyasu/hyde
//! [`auth-hook`]: https://github.com/n0-computer/iroh/blob/main/iroh/examples/auth-hook.rs

mod error;
mod incoming;
mod mutual;
mod outgoing;
mod signer;
mod util;
mod verifier;
mod wire;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use incoming::{incoming, AuthProtocol, IncomingAuthHook};
pub use mutual::{mutual, MutualAuthHook, MutualAuthProtocol, MutualAuthTask};
pub use outgoing::{outgoing, OutgoingAuthHook, OutgoingAuthTask};
pub use signer::{HydeSigner, InstitutionalSigner};
pub use util::TaskGuard;
pub use verifier::{HydeVerifier, InstitutionId, InstitutionVerifier, Roster, VerifyError};
pub use wire::{ALPN, MUTUAL_ALPN};

// Re-export the hyde knobs callers need so they don't have to depend on
// `hyde-tee` directly just to pick a fallback policy or algorithm.
pub use hyde::{FallbackPolicy, SigningAlgorithm};
