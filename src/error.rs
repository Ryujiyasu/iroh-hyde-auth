//! Error types for the auth handshake.

/// Errors that can occur while running the institutional auth handshake.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An iroh connection / stream operation failed.
    #[error("transport error: {0}")]
    Transport(String),

    /// A wire message could not be (de)serialized.
    #[error("codec error: {0}")]
    Codec(#[from] postcard::Error),

    /// A length-prefixed message exceeded the allowed maximum.
    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),

    /// The peer spoke an unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    Version(u8),

    /// The institutional assertion timestamp drifted outside the allowed window.
    #[error("clock skew outside allowed window")]
    ClockSkew,

    /// The local institutional signer failed to produce a signature.
    #[error("institutional signer failed: {0}")]
    Signer(String),

    /// The remote failed verification (untrusted key, bad signature, revoked, …).
    #[error("authentication denied: {0}")]
    Denied(String),

    /// The authenticator background task is no longer running.
    #[error("authenticator task stopped")]
    AuthenticatorStopped,
}

/// Convenience result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Map any error that implements [`std::fmt::Display`] into [`Error::Transport`].
pub(crate) fn transport<E: std::fmt::Display>(e: E) -> Error {
    Error::Transport(e.to_string())
}
