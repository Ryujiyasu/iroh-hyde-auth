//! End-to-end tests over real (loopback) iroh endpoints, with the n0 relay and
//! address discovery disabled so they run fully offline.
//!
//! ```text
//! cargo test --no-default-features --features software --test e2e
//! ```
#![cfg(feature = "software")]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh::{
    endpoint::presets, protocol::Router, Endpoint, EndpointAddr, RelayMode,
};
use iroh_hyde_auth::{
    mutual, FallbackPolicy, HydeSigner, HydeVerifier, InstitutionalSigner, Roster, TaskGuard,
    MUTUAL_ALPN,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxErr>;

/// Build a node running mutual auth in front of echo, bound to loopback only.
async fn node(signer: Arc<HydeSigner>, roster: Roster) -> Result<(Router, TaskGuard)> {
    let verifier = Arc::new(HydeVerifier::new(roster));
    let (hook, protocol, task) = mutual(signer, verifier);
    let endpoint = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())?
        .hooks(hook)
        .bind()
        .await?;
    let guard = task.spawn(endpoint.clone());
    let router = Router::builder(endpoint)
        .accept(MUTUAL_ALPN, protocol)
        .accept(echo::ALPN, echo::Echo)
        .spawn();
    Ok((router, guard))
}

/// Full dialable address (id + loopback direct addresses), no discovery needed.
fn full_addr(ep: &Endpoint) -> EndpointAddr {
    let mut addr = EndpointAddr::new(ep.id());
    for sock in ep.bound_sockets() {
        if sock.ip().is_loopback() {
            addr = addr.with_ip_addr(sock);
        }
    }
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_auth_admits_trusted_peer() -> Result<()> {
    let a = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);
    let b = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);

    let mut roster_a = Roster::new();
    roster_a.insert(b.verifying_key(), "b");
    let mut roster_b = Roster::new();
    roster_b.insert(a.verifying_key(), "a");

    let (node_b, _gb) = node(b, roster_b).await?;
    let (node_a, _ga) = node(a, roster_a).await?;

    // A dials B's echo; mutual auth must complete first, transparently.
    let addr_b = full_addr(node_b.endpoint());
    let resp = tokio::time::timeout(
        Duration::from_secs(15),
        echo::Echo::connect(node_a.endpoint(), addr_b, b"mutual hello"),
    )
    .await
    .map_err(|_| -> BoxErr { "timed out waiting for echo".into() })??;
    assert_eq!(resp, b"mutual hello");

    // And the reverse direction works too (mutual is symmetric).
    let addr_a = full_addr(node_a.endpoint());
    let resp = tokio::time::timeout(
        Duration::from_secs(15),
        echo::Echo::connect(node_b.endpoint(), addr_a, b"reverse hello"),
    )
    .await
    .map_err(|_| -> BoxErr { "timed out waiting for reverse echo".into() })??;
    assert_eq!(resp, b"reverse hello");

    node_a.shutdown().await?;
    node_b.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_auth_rejects_untrusted_peer() -> Result<()> {
    let b = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);
    let outsider = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);

    // B trusts nobody relevant; the outsider trusts nobody. Both directions fail.
    let (node_b, _gb) = node(b, Roster::new()).await?;
    let (node_c, _gc) = node(outsider, Roster::new()).await?;

    let addr_b = full_addr(node_b.endpoint());
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        echo::Echo::connect(node_c.endpoint(), addr_b, b"let me in"),
    )
    .await
    .map_err(|_| -> BoxErr { "timed out (connection should fail fast, not hang)".into() })?;
    assert!(
        result.is_err(),
        "untrusted peer must not reach the echo protocol"
    );

    node_b.shutdown().await?;
    node_c.shutdown().await?;
    Ok(())
}

mod echo {
    use iroh::{
        endpoint::Connection,
        protocol::{AcceptError, ProtocolHandler},
        Endpoint, EndpointAddr,
    };

    pub const ALPN: &[u8] = b"iroh-hyde-auth-test/echo/0";

    #[derive(Debug, Clone)]
    pub struct Echo;

    impl Echo {
        pub async fn connect(
            endpoint: &Endpoint,
            remote: impl Into<EndpointAddr>,
            message: &[u8],
        ) -> super::Result<Vec<u8>> {
            let conn = endpoint.connect(remote, ALPN).await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            send.write_all(message).await?;
            send.finish()?;
            let response = recv.read_to_end(1000).await?;
            conn.close(0u32.into(), b"bye");
            Ok(response)
        }
    }

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = connection.accept_bi().await?;
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            connection.closed().await;
            Ok(())
        }
    }
}
