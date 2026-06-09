//! Initiator side: pre-authenticate outgoing connections before the
//! application protocol is dialed.

use std::{
    collections::{hash_map, HashMap, HashSet},
    sync::Arc,
};

use iroh::{
    endpoint::{BeforeConnectOutcome, ConnectionError, EndpointHooks},
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
    wire::{
        read_msg, transcript, write_msg, ClientAuth, ClientHello, CLOSE_ACCEPTED, CLOSE_DENIED,
        ENDPOINT_ID_LEN, MAX_MSG, PROTOCOL_VERSION,
    },
};

/// Build the initiator-side hook and its companion task.
///
/// Mount the returned [`OutgoingAuthHook`] on the endpoint builder via
/// `.hooks(..)`, then call [`OutgoingAuthTask::spawn`] once the endpoint is
/// bound. Any non-auth outgoing connection then transparently runs the
/// institutional handshake first.
pub fn outgoing(signer: Arc<dyn InstitutionalSigner>) -> (OutgoingAuthHook, OutgoingAuthTask) {
    let (tx, rx) = mpsc::channel(16);
    let hook = OutgoingAuthHook { tx };
    let task = OutgoingAuthTask {
        signer,
        rx,
        allowed_remotes: HashSet::new(),
        pending_remotes: HashMap::new(),
        tasks: JoinSet::new(),
    };
    (hook, task)
}

type AuthResult = std::result::Result<(), Arc<Error>>;

/// Endpoint hook that gates outgoing connections on a prior auth handshake.
#[derive(Debug)]
pub struct OutgoingAuthHook {
    tx: mpsc::Sender<(EndpointAddr, oneshot::Sender<AuthResult>)>,
}

impl OutgoingAuthHook {
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

impl EndpointHooks for OutgoingAuthHook {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        // Never intercept the auth handshake itself, or we would recurse.
        if alpn == crate::ALPN {
            return BeforeConnectOutcome::Accept;
        }
        // Pass the full address (with direct addresses) so the auth connection
        // resolves the same way the application connection would.
        match self.authenticate(remote_addr.clone()).await {
            Ok(()) => BeforeConnectOutcome::Accept,
            Err(err) => {
                debug!("outgoing auth denied for {}: {err:#}", remote_addr.id);
                BeforeConnectOutcome::Reject
            }
        }
    }
}

/// Background task that runs the institutional handshake and caches the result
/// per remote so repeated connections only authenticate once.
pub struct OutgoingAuthTask {
    signer: Arc<dyn InstitutionalSigner>,
    rx: mpsc::Receiver<(EndpointAddr, oneshot::Sender<AuthResult>)>,
    allowed_remotes: HashSet<EndpointId>,
    pending_remotes: HashMap<EndpointId, Vec<oneshot::Sender<AuthResult>>>,
    tasks: JoinSet<(EndpointId, Result<()>)>,
}

impl OutgoingAuthTask {
    /// Spawn the task. Keep the returned guard alive for as long as the endpoint
    /// should be able to dial authenticated peers.
    pub fn spawn(self, endpoint: Endpoint) -> TaskGuard {
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
                    let (remote_id, res) = joined.expect("auth connect task panicked");
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
        if self.allowed_remotes.contains(&remote_id) {
            tx.send(Ok(())).ok();
            return;
        }
        match self.pending_remotes.entry(remote_id) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(tx),
            hash_map::Entry::Vacant(entry) => {
                let endpoint = endpoint.clone();
                let signer = self.signer.clone();
                self.tasks.spawn(async move {
                    let res = handshake(endpoint, remote_addr, signer).await;
                    (remote_id, res)
                });
                entry.insert(vec![tx]);
            }
        }
    }

    fn handle_completion(&mut self, remote_id: EndpointId, res: AuthResult) {
        if res.is_ok() {
            self.allowed_remotes.insert(remote_id);
        }
        if let Some(waiters) = self.pending_remotes.remove(&remote_id) {
            for tx in waiters {
                tx.send(res.clone()).ok();
            }
        }
    }
}

/// Run the institutional handshake against `remote_id` over the auth ALPN.
async fn handshake(
    endpoint: Endpoint,
    remote_addr: EndpointAddr,
    signer: Arc<dyn InstitutionalSigner>,
) -> Result<()> {
    let conn = endpoint
        .connect(remote_addr, crate::ALPN)
        .await
        .map_err(transport)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;

    // 1. Greet (also triggers the acceptor's `accept_bi`).
    write_msg(&mut send, &ClientHello { version: PROTOCOL_VERSION }).await?;

    // 2. Receive the fresh challenge.
    let challenge: crate::wire::ServerChallenge = read_msg(&mut recv, MAX_MSG).await?;
    if challenge.version != PROTOCOL_VERSION {
        return Err(Error::Version(challenge.version));
    }

    // 3. Sign the transcript binding the nonce to *our* ephemeral endpoint id.
    let my_id = endpoint.id();
    let id_bytes: &[u8; ENDPOINT_ID_LEN] = my_id.as_bytes();
    let now = unix_secs();
    let message = transcript(&challenge.nonce, id_bytes, now);
    let signature = crate::signer::sign_blocking(&signer, &message).await?;
    write_msg(
        &mut send,
        &ClientAuth {
            verifying_key: signer.verifying_key(),
            signature,
            client_unix_secs: now,
        },
    )
    .await?;
    send.finish().map_err(transport)?;

    // 4. The acceptor signals the verdict by the connection close code.
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
