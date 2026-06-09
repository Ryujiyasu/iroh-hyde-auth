//! Mutual institutional authentication: both peers prove *and* verify each
//! other's institution in a single auth-ALPN exchange, and a combined hook
//! gates application connections in both directions.
//!
//! Use this when neither side is purely a client — e.g. hospital ↔ hospital,
//! where each endpoint must be sure of the other's institution before any
//! application protocol runs.
//!
//! Each endpoint mounts:
//! * the [`MutualAuthHook`] (`before_connect` to authenticate outward,
//!   `after_handshake` to gate inward), and
//! * the [`MutualAuthProtocol`] on [`MUTUAL_ALPN`], and
//! * runs the [`MutualAuthTask`] (which also publishes the endpoint's own id to
//!   the acceptor side — so it must be spawned).
//!
//! [`MUTUAL_ALPN`]: crate::MUTUAL_ALPN

use std::{
    collections::{hash_map, HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
};

use iroh::{
    endpoint::{
        AfterHandshakeOutcome, BeforeConnectOutcome, Connection, ConnectionError, EndpointHooks,
    },
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointAddr, EndpointId,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tracing::debug;

use crate::{
    error::{transport, Error, Result},
    signer::InstitutionalSigner,
    util::{unix_secs, TaskGuard},
    verifier::InstitutionVerifier,
    wire::{
        mutual_transcript, read_msg, write_msg, MutualChallenge, MutualHello, MutualResponse,
        CLOSE_ACCEPTED, CLOSE_DENIED, MAX_MSG, MUTUAL_ALPN, NONCE_LEN, PROTOCOL_VERSION,
        ROLE_ACCEPTOR, ROLE_INITIATOR,
    },
};

/// Default tolerance (seconds) for a peer's asserted timestamp.
const DEFAULT_MAX_SKEW_SECS: u64 = 300;

type AuthResult = std::result::Result<(), Arc<Error>>;

/// Shared, mutually-authenticated peer set + this endpoint's own id.
#[derive(Debug, Clone, Default)]
struct Shared {
    allowed: Arc<Mutex<HashSet<EndpointId>>>,
    local_id: Arc<OnceLock<EndpointId>>,
}

/// Build the three pieces for mutual auth on one endpoint.
///
/// Mount [`MutualAuthHook`] via `.hooks(..)`, mount [`MutualAuthProtocol`] on
/// the router at [`MUTUAL_ALPN`], and call [`MutualAuthTask::spawn`] once the
/// endpoint is bound (spawning also activates this endpoint's institutional
/// identity for the acceptor side).
///
/// [`MUTUAL_ALPN`]: crate::MUTUAL_ALPN
pub fn mutual(
    signer: Arc<dyn InstitutionalSigner>,
    verifier: Arc<dyn InstitutionVerifier>,
) -> (MutualAuthHook, MutualAuthProtocol, MutualAuthTask) {
    let shared = Shared::default();
    let (tx, rx) = mpsc::channel(16);

    let hook = MutualAuthHook {
        tx,
        allowed: shared.allowed.clone(),
    };
    let protocol = MutualAuthProtocol {
        signer: signer.clone(),
        verifier: verifier.clone(),
        shared: shared.clone(),
        max_skew_secs: Some(DEFAULT_MAX_SKEW_SECS),
    };
    let task = MutualAuthTask {
        signer,
        verifier,
        rx,
        shared,
        pending: HashMap::new(),
        tasks: JoinSet::new(),
        max_skew_secs: Some(DEFAULT_MAX_SKEW_SECS),
    };
    (hook, protocol, task)
}

/// Combined endpoint hook: authenticates outgoing connections and gates
/// incoming ones, both against the shared mutually-authenticated peer set.
#[derive(Debug)]
pub struct MutualAuthHook {
    tx: mpsc::Sender<(EndpointAddr, oneshot::Sender<AuthResult>)>,
    allowed: Arc<Mutex<HashSet<EndpointId>>>,
}

impl MutualAuthHook {
    async fn authenticate(&self, remote_addr: EndpointAddr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send((remote_addr, tx))
            .await
            .map_err(|_| Error::AuthenticatorStopped)?;
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::Denied(e.to_string())),
            Err(_) => Err(Error::AuthenticatorStopped),
        }
    }
}

impl EndpointHooks for MutualAuthHook {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if alpn == MUTUAL_ALPN {
            return BeforeConnectOutcome::Accept;
        }
        // Pass the full address (with direct addresses) so the auth connection
        // resolves the same way the application connection would — no reliance
        // on discovery.
        match self.authenticate(remote_addr.clone()).await {
            Ok(()) => BeforeConnectOutcome::Accept,
            Err(err) => {
                debug!("mutual auth (outgoing) denied for {}: {err:#}", remote_addr.id);
                BeforeConnectOutcome::Reject
            }
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        let permitted = conn.alpn() == MUTUAL_ALPN
            || self
                .allowed
                .lock()
                .expect("allowed poisoned")
                .contains(&conn.remote_id());
        if permitted {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"not mutually authenticated".to_vec(),
            }
        }
    }
}

/// Acceptor side of the mutual handshake. Mount on the router at [`MUTUAL_ALPN`].
///
/// [`MUTUAL_ALPN`]: crate::MUTUAL_ALPN
#[derive(Debug, Clone)]
pub struct MutualAuthProtocol {
    signer: Arc<dyn InstitutionalSigner>,
    verifier: Arc<dyn InstitutionVerifier>,
    shared: Shared,
    max_skew_secs: Option<u64>,
}

impl MutualAuthProtocol {
    /// Tolerance for the peer's asserted timestamp. `None` disables the check
    /// (the random nonces still prevent replay).
    pub fn with_max_skew(mut self, secs: Option<u64>) -> Self {
        self.max_skew_secs = secs;
        self
    }

    async fn handshake(&self, conn: &Connection) -> Result<EndpointId> {
        let local_id = self.shared.local_id.get().copied().ok_or_else(|| {
            Error::Signer("local endpoint id not set — spawn the MutualAuthTask".into())
        })?;

        let (mut send, mut recv) = conn.accept_bi().await.map_err(transport)?;
        let hello: MutualHello = read_msg(&mut recv, MAX_MSG).await?;
        if hello.version != PROTOCOL_VERSION {
            return Err(Error::Version(hello.version));
        }

        // Prove ourselves to the initiator, bound to its nonce.
        let nonce_b: [u8; NONCE_LEN] = rand::random();
        let time_b = unix_secs();
        let b_transcript =
            mutual_transcript(ROLE_ACCEPTOR, &hello.nonce, local_id.as_bytes(), time_b);
        let sig_b = self.signer.sign(&b_transcript)?;
        write_msg(
            &mut send,
            &MutualChallenge {
                version: PROTOCOL_VERSION,
                nonce: nonce_b,
                verifying_key: self.signer.verifying_key(),
                signature: sig_b,
                acceptor_unix_secs: time_b,
            },
        )
        .await?;

        // Verify the initiator, bound to our nonce and its QUIC-authenticated id.
        let response: MutualResponse = read_msg(&mut recv, MAX_MSG).await?;
        if let Some(max) = self.max_skew_secs {
            if unix_secs().abs_diff(response.initiator_unix_secs) > max {
                return Err(Error::ClockSkew);
            }
        }
        let remote_id = conn.remote_id();
        let a_transcript = mutual_transcript(
            ROLE_INITIATOR,
            &nonce_b,
            remote_id.as_bytes(),
            response.initiator_unix_secs,
        );
        self.verifier
            .verify(&response.verifying_key, &a_transcript, &response.signature)
            .map_err(|e| Error::Denied(e.to_string()))?;
        Ok(remote_id)
    }
}

impl ProtocolHandler for MutualAuthProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        match self.handshake(&connection).await {
            Ok(remote) => {
                self.shared
                    .allowed
                    .lock()
                    .expect("allowed poisoned")
                    .insert(remote);
                debug!("mutually authenticated {remote} (acceptor side)");
                connection.close(CLOSE_ACCEPTED.into(), b"accepted");
            }
            Err(err) => {
                debug!("mutual auth (acceptor) denied: {err:#}");
                connection.close(CLOSE_DENIED.into(), b"denied");
            }
        }
        Ok(())
    }
}

/// Background task that drives outgoing mutual handshakes, de-duplicating
/// concurrent dials and caching results in the shared peer set.
pub struct MutualAuthTask {
    signer: Arc<dyn InstitutionalSigner>,
    verifier: Arc<dyn InstitutionVerifier>,
    rx: mpsc::Receiver<(EndpointAddr, oneshot::Sender<AuthResult>)>,
    shared: Shared,
    pending: HashMap<EndpointId, Vec<oneshot::Sender<AuthResult>>>,
    tasks: JoinSet<(EndpointId, Result<()>)>,
    max_skew_secs: Option<u64>,
}

impl MutualAuthTask {
    /// Spawn the task and publish this endpoint's id for the acceptor side.
    /// Keep the returned guard alive for as long as the endpoint should be able
    /// to authenticate peers.
    pub fn spawn(self, endpoint: Endpoint) -> TaskGuard {
        // Activate the acceptor side's own institutional identity binding.
        self.shared.local_id.set(endpoint.id()).ok();
        TaskGuard::new(tokio::spawn(self.run(endpoint)))
    }

    async fn run(mut self, endpoint: Endpoint) {
        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    let Some((remote_addr, tx)) = msg else { break };
                    self.handle_request(&endpoint, remote_addr, tx);
                }
                Some(joined) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let (remote_id, res) = joined.expect("mutual handshake task panicked");
                    self.handle_completion(remote_id, res.map_err(Arc::new));
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        endpoint: &Endpoint,
        remote_addr: EndpointAddr,
        tx: oneshot::Sender<AuthResult>,
    ) {
        let remote_id = remote_addr.id;
        if self
            .shared
            .allowed
            .lock()
            .expect("allowed poisoned")
            .contains(&remote_id)
        {
            tx.send(Ok(())).ok();
            return;
        }
        match self.pending.entry(remote_id) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(tx),
            hash_map::Entry::Vacant(entry) => {
                let endpoint = endpoint.clone();
                let signer = self.signer.clone();
                let verifier = self.verifier.clone();
                let max_skew = self.max_skew_secs;
                self.tasks.spawn(async move {
                    let res = handshake(endpoint, remote_addr, signer, verifier, max_skew).await;
                    (remote_id, res)
                });
                entry.insert(vec![tx]);
            }
        }
    }

    fn handle_completion(&mut self, remote_id: EndpointId, res: AuthResult) {
        if res.is_ok() {
            self.shared
                .allowed
                .lock()
                .expect("allowed poisoned")
                .insert(remote_id);
        }
        if let Some(waiters) = self.pending.remove(&remote_id) {
            for tx in waiters {
                tx.send(res.clone()).ok();
            }
        }
    }
}

/// Initiator side of the mutual handshake over [`MUTUAL_ALPN`].
async fn handshake(
    endpoint: Endpoint,
    remote_addr: EndpointAddr,
    signer: Arc<dyn InstitutionalSigner>,
    verifier: Arc<dyn InstitutionVerifier>,
    max_skew_secs: Option<u64>,
) -> Result<()> {
    let conn = endpoint
        .connect(remote_addr, MUTUAL_ALPN)
        .await
        .map_err(transport)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;

    // 1. Greet with our nonce.
    let nonce_a: [u8; NONCE_LEN] = rand::random();
    write_msg(
        &mut send,
        &MutualHello {
            version: PROTOCOL_VERSION,
            nonce: nonce_a,
        },
    )
    .await?;

    // 2. Receive and verify the acceptor's assertion.
    let challenge: MutualChallenge = read_msg(&mut recv, MAX_MSG).await?;
    if challenge.version != PROTOCOL_VERSION {
        conn.close(CLOSE_DENIED.into(), b"version");
        return Err(Error::Version(challenge.version));
    }
    if let Some(max) = max_skew_secs {
        if unix_secs().abs_diff(challenge.acceptor_unix_secs) > max {
            conn.close(CLOSE_DENIED.into(), b"skew");
            return Err(Error::ClockSkew);
        }
    }
    let peer_id = conn.remote_id();
    let b_transcript = mutual_transcript(
        ROLE_ACCEPTOR,
        &nonce_a,
        peer_id.as_bytes(),
        challenge.acceptor_unix_secs,
    );
    if let Err(e) =
        verifier.verify(&challenge.verifying_key, &b_transcript, &challenge.signature)
    {
        // We reject the acceptor: close without responding so it never records us.
        conn.close(CLOSE_DENIED.into(), b"peer-untrusted");
        return Err(Error::Denied(format!("acceptor failed verification: {e}")));
    }

    // 3. Prove ourselves, bound to the acceptor's nonce.
    let my_id = endpoint.id();
    let time_a = unix_secs();
    let a_transcript = mutual_transcript(ROLE_INITIATOR, &challenge.nonce, my_id.as_bytes(), time_a);
    let sig_a = signer.sign(&a_transcript)?;
    write_msg(
        &mut send,
        &MutualResponse {
            verifying_key: signer.verifying_key(),
            signature: sig_a,
            initiator_unix_secs: time_a,
        },
    )
    .await?;
    send.finish().map_err(transport)?;

    // 4. The acceptor's verdict on us.
    let reason = conn.closed().await;
    if let ConnectionError::ApplicationClosed(code) = &reason {
        let c = code.error_code.into_inner() as u32;
        if c == CLOSE_ACCEPTED {
            return Ok(());
        } else if c == CLOSE_DENIED {
            return Err(Error::Denied("rejected by remote acceptor".into()));
        }
    }
    Err(transport(reason))
}
