//! Acceptor side: only admit application connections from peers that have
//! completed the institutional handshake.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use iroh::{
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks},
    protocol::{AcceptError, ProtocolHandler},
    EndpointId,
};
use tracing::debug;

use crate::{
    error::{transport, Error, Result},
    util::unix_secs,
    verifier::{InstitutionId, InstitutionVerifier},
    wire::{
        read_msg, transcript, write_msg, ClientAuth, ClientHello, ServerChallenge, CLOSE_ACCEPTED,
        CLOSE_DENIED, ENDPOINT_ID_LEN, MAX_MSG, NONCE_LEN, PROTOCOL_VERSION,
    },
};

/// Default tolerance (seconds) for the initiator's asserted timestamp.
const DEFAULT_MAX_SKEW_SECS: u64 = 300;

/// Build the acceptor-side hook and the auth protocol handler.
///
/// Mount the [`IncomingAuthHook`] on the endpoint builder via `.hooks(..)` and
/// the [`AuthProtocol`] on the router via `.accept(iroh_hyde_auth::ALPN, ..)`.
/// They share a set of already-authenticated remotes.
pub fn incoming(verifier: Arc<dyn InstitutionVerifier>) -> (IncomingAuthHook, AuthProtocol) {
    let allowed_remotes: Arc<Mutex<HashSet<EndpointId>>> = Default::default();
    let hook = IncomingAuthHook {
        allowed_remotes: allowed_remotes.clone(),
    };
    let protocol = AuthProtocol {
        verifier,
        allowed_remotes,
        max_skew_secs: Some(DEFAULT_MAX_SKEW_SECS),
    };
    (hook, protocol)
}

/// Endpoint hook that rejects application connections from peers that have not
/// authenticated. Auth-ALPN connections are always allowed through (that is how
/// peers authenticate in the first place).
#[derive(Debug)]
pub struct IncomingAuthHook {
    allowed_remotes: Arc<Mutex<HashSet<EndpointId>>>,
}

impl EndpointHooks for IncomingAuthHook {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let permitted = conn.alpn() == crate::ALPN
            || self
                .allowed_remotes
                .lock()
                .expect("allowed_remotes poisoned")
                .contains(&conn.remote_id());
        if permitted {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"not authenticated".to_vec(),
            }
        }
    }
}

/// Protocol handler that runs the institutional challenge–response and records
/// successfully authenticated remotes.
#[derive(Debug, Clone)]
pub struct AuthProtocol {
    verifier: Arc<dyn InstitutionVerifier>,
    allowed_remotes: Arc<Mutex<HashSet<EndpointId>>>,
    max_skew_secs: Option<u64>,
}

impl AuthProtocol {
    /// Set the tolerance for the initiator's asserted timestamp. `None` disables
    /// the freshness check entirely (the random nonce still prevents replay).
    pub fn with_max_skew(mut self, secs: Option<u64>) -> Self {
        self.max_skew_secs = secs;
        self
    }

    async fn run_handshake(&self, connection: &Connection) -> Result<InstitutionId> {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(transport)?;

        let hello: ClientHello = read_msg(&mut recv, MAX_MSG).await?;
        if hello.version != PROTOCOL_VERSION {
            return Err(Error::Version(hello.version));
        }

        let nonce: [u8; NONCE_LEN] = rand::random();
        let server_now = unix_secs();
        write_msg(
            &mut send,
            &ServerChallenge {
                version: PROTOCOL_VERSION,
                nonce,
                server_unix_secs: server_now,
            },
        )
        .await?;

        let auth: ClientAuth = read_msg(&mut recv, MAX_MSG).await?;
        if let Some(max) = self.max_skew_secs {
            if server_now.abs_diff(auth.client_unix_secs) > max {
                return Err(Error::ClockSkew);
            }
        }

        // Bind to the QUIC-authenticated remote id, never to anything the client
        // claims — this is what ties the institution to *this* transport session.
        let remote_id = connection.remote_id();
        let id_bytes: &[u8; ENDPOINT_ID_LEN] = remote_id.as_bytes();
        let message = transcript(&nonce, id_bytes, auth.client_unix_secs);

        self.verifier
            .verify(&auth.verifying_key, &message, &auth.signature)
            .map_err(|e| Error::Denied(e.to_string()))
    }
}

impl ProtocolHandler for AuthProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        match self.run_handshake(&connection).await {
            Ok(institution) => {
                self.allowed_remotes
                    .lock()
                    .expect("allowed_remotes poisoned")
                    .insert(connection.remote_id());
                debug!(
                    "authenticated {} as institution {institution:?}",
                    connection.remote_id()
                );
                connection.close(CLOSE_ACCEPTED.into(), b"accepted");
            }
            Err(err) => {
                debug!("incoming auth denied: {err:#}");
                connection.close(CLOSE_DENIED.into(), b"denied");
            }
        }
        Ok(())
    }
}
