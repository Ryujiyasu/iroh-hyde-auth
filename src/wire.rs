//! On-the-wire protocol for the institutional auth handshake.
//!
//! The handshake runs over its own ALPN ([`ALPN`]) on a *separate* connection
//! from the application protocol. The application protocol (echo, iroh-blobs,
//! iroh-gossip, …) never sees any of this.
//!
//! Flow (one bidirectional stream):
//!
//! ```text
//!   initiator                                  acceptor
//!      |  ClientHello { version }  ───────────────▶ |
//!      | ◀─────  ServerChallenge { nonce, time }    |
//!      |  ClientAuth { vkey, sig, time }  ────────▶ |
//!      | ◀── connection close: 1 (ok) / 403 (deny)  |
//! ```
//!
//! The signed transcript binds the institutional signature to (a) the
//! acceptor's fresh random nonce and (b) the initiator's *ephemeral* endpoint
//! id. Because iroh's QUIC/TLS handshake already proves the peer holds the
//! secret key for that endpoint id, binding to it means a relay or
//! man-in-the-middle cannot present a stolen institutional assertion for a
//! transport session it does not control.

use serde::{Deserialize, Serialize};

use iroh::endpoint::{RecvStream, SendStream};

use crate::error::{transport, Error, Result};

/// ALPN for the auth handshake. Mount the [`crate::AuthProtocol`] on this.
pub const ALPN: &[u8] = b"iroh-hyde-auth/0";

/// Current protocol version.
pub(crate) const PROTOCOL_VERSION: u8 = 0;

/// Domain-separation tag mixed into every signed transcript.
pub(crate) const DOMAIN: &[u8] = b"iroh-hyde-auth/v0/institutional-challenge";

/// Length of the acceptor's random challenge nonce.
pub(crate) const NONCE_LEN: usize = 32;

/// Length of an iroh endpoint id (ed25519 public key) in bytes.
pub(crate) const ENDPOINT_ID_LEN: usize = 32;

/// Close code sent by the acceptor when authentication succeeds.
pub(crate) const CLOSE_ACCEPTED: u32 = 1;
/// Close code sent by the acceptor when authentication fails.
pub(crate) const CLOSE_DENIED: u32 = 403;

/// Maximum size of a single length-prefixed wire message.
///
/// ML-DSA-65 verifying keys (~1952 B) and signatures (~3309 B) dominate; 16 KiB
/// leaves generous headroom for larger parameter sets.
pub(crate) const MAX_MSG: usize = 16 * 1024;

/// First message: the initiator greets the acceptor (also triggers `accept_bi`).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ClientHello {
    pub version: u8,
}

/// Second message: the acceptor's fresh challenge.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ServerChallenge {
    pub version: u8,
    pub nonce: [u8; NONCE_LEN],
    pub server_unix_secs: u64,
}

/// Third message: the initiator's institutional assertion.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ClientAuth {
    /// The institution's publishable verifying key (ML-DSA).
    pub verifying_key: Vec<u8>,
    /// Signature over [`transcript`].
    pub signature: Vec<u8>,
    /// The initiator's asserted timestamp (bound into the transcript).
    pub client_unix_secs: u64,
}

/// Build the canonical byte string that the initiator signs and the acceptor
/// re-derives and verifies. Both sides MUST construct this identically.
///
/// * `nonce` — the acceptor's challenge.
/// * `initiator_id` — the initiator's ephemeral endpoint id. The acceptor uses
///   the QUIC-authenticated `connection.remote_id()`, **not** anything the
///   client claims, which is what binds institution → transport session.
/// * `client_unix_secs` — the initiator's asserted timestamp.
pub(crate) fn transcript(
    nonce: &[u8; NONCE_LEN],
    initiator_id: &[u8; ENDPOINT_ID_LEN],
    client_unix_secs: u64,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DOMAIN.len() + 1 + NONCE_LEN + ENDPOINT_ID_LEN + 8);
    t.extend_from_slice(DOMAIN);
    t.push(PROTOCOL_VERSION);
    t.extend_from_slice(nonce);
    t.extend_from_slice(initiator_id);
    t.extend_from_slice(&client_unix_secs.to_be_bytes());
    t
}

// ---------------------------------------------------------------------------
// Mutual handshake (both peers prove and verify in one exchange).
// ---------------------------------------------------------------------------

/// ALPN for the *mutual* auth handshake. Distinct from [`ALPN`] so a
/// one-directional initiator and a mutual acceptor never mis-parse each other.
pub const MUTUAL_ALPN: &[u8] = b"iroh-hyde-auth/mutual/0";

/// Domain-separation tag for mutual transcripts.
pub(crate) const DOMAIN_MUTUAL: &[u8] = b"iroh-hyde-auth/v0/mutual-challenge";

/// Role of the signer in the mutual handshake. Mixed into the transcript so a
/// signature produced in one role cannot be reflected as the other.
pub(crate) const ROLE_INITIATOR: u8 = 1; // dialled the auth connection
pub(crate) const ROLE_ACCEPTOR: u8 = 2; // accepted the auth connection

/// Message 1, initiator → acceptor: greet and send the initiator's nonce.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MutualHello {
    pub version: u8,
    pub nonce: [u8; NONCE_LEN],
}

/// Message 2, acceptor → initiator: the acceptor's nonce *and* its own
/// institutional assertion (bound to the initiator's nonce).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MutualChallenge {
    pub version: u8,
    pub nonce: [u8; NONCE_LEN],
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub acceptor_unix_secs: u64,
}

/// Message 3, initiator → acceptor: the initiator's institutional assertion
/// (bound to the acceptor's nonce).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MutualResponse {
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub initiator_unix_secs: u64,
}

/// Build a mutual transcript. The signer asserts: *"institution `vk` operates
/// endpoint `signer_id`, fresh with respect to `peer_nonce`, at `time`, acting
/// as `role`."* The verifier rebuilds it with the peer's role, the nonce it
/// itself generated, and the QUIC-authenticated `remote_id` as `signer_id`.
pub(crate) fn mutual_transcript(
    role: u8,
    peer_nonce: &[u8; NONCE_LEN],
    signer_id: &[u8; ENDPOINT_ID_LEN],
    time: u64,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DOMAIN_MUTUAL.len() + 2 + NONCE_LEN + ENDPOINT_ID_LEN + 8);
    t.extend_from_slice(DOMAIN_MUTUAL);
    t.push(PROTOCOL_VERSION);
    t.push(role);
    t.extend_from_slice(peer_nonce);
    t.extend_from_slice(signer_id);
    t.extend_from_slice(&time.to_be_bytes());
    t
}

/// Write a length-prefixed, postcard-encoded message.
pub(crate) async fn write_msg<T: Serialize>(send: &mut SendStream, msg: &T) -> Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    let len = u32::try_from(bytes.len()).map_err(|_| Error::MessageTooLarge(bytes.len()))?;
    send.write_all(&len.to_be_bytes()).await.map_err(transport)?;
    send.write_all(&bytes).await.map_err(transport)?;
    Ok(())
}

/// Read a length-prefixed, postcard-encoded message (bounded by [`MAX_MSG`]).
pub(crate) async fn read_msg<T: serde::de::DeserializeOwned>(
    recv: &mut RecvStream,
    max: usize,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(transport)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(Error::MessageTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(transport)?;
    Ok(postcard::from_bytes(&buf)?)
}
