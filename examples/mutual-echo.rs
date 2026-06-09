//! End-to-end demo of **mutual** institutional auth.
//!
//! Two nodes each carry their own TPM-bound institution and a roster trusting
//! the other. When either dials the other's echo protocol, a single auth-ALPN
//! exchange has *both* sides prove and verify each other before echo runs. A
//! third node, trusted by no one, is rejected in both directions.
//!
//! Run (needs a `software` backend and network for the n0 preset):
//!
//! ```text
//! cargo run --example mutual-echo --features software
//! ```

use std::sync::Arc;

use iroh::{endpoint::presets, protocol::Router, Endpoint};
use iroh_hyde_auth::{
    mutual, FallbackPolicy, HydeSigner, HydeVerifier, InstitutionalSigner, Roster, TaskGuard,
    MUTUAL_ALPN,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let hospital_a = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);
    let hospital_b = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);
    let outsider = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);

    // Each hospital trusts only the other.
    let mut roster_a = Roster::new();
    roster_a.insert(hospital_b.verifying_key(), "hospital-b");
    let mut roster_b = Roster::new();
    roster_b.insert(hospital_a.verifying_key(), "hospital-a");

    let (node_a, _guard_a) = build_node(hospital_a, roster_a).await?;
    let (node_b, _guard_b) = build_node(hospital_b.clone(), roster_b).await?;
    node_a.endpoint().online().await;
    node_b.endpoint().online().await;
    let addr_a = node_a.endpoint().addr();
    let addr_b = node_b.endpoint().addr();

    println!("-- A -> B (mutually trusted) --");
    match echo::Echo::connect(node_a.endpoint(), addr_b.clone(), b"ping from A").await {
        Ok(resp) => println!("  ok: {:?}", String::from_utf8_lossy(&resp)),
        Err(e) => println!("  UNEXPECTED failure: {e}"),
    }

    println!("-- B -> A (mutually trusted, other direction) --");
    match echo::Echo::connect(node_b.endpoint(), addr_a.clone(), b"ping from B").await {
        Ok(resp) => println!("  ok: {:?}", String::from_utf8_lossy(&resp)),
        Err(e) => println!("  UNEXPECTED failure: {e}"),
    }

    println!("-- outsider -> B (trusted by no one) --");
    // The outsider trusts no one and is trusted by no one.
    let (node_c, _guard_c) = build_node(outsider, Roster::new()).await?;
    node_c.endpoint().online().await;
    match echo::Echo::connect(node_c.endpoint(), addr_b.clone(), b"ping from C").await {
        Ok(_) => println!("  UNEXPECTED: outsider admitted"),
        Err(e) => println!("  rejected as expected: {e}"),
    }

    node_a.shutdown().await?;
    node_b.shutdown().await?;
    node_c.shutdown().await?;
    Ok(())
}

/// Build a node that runs mutual institutional auth in front of echo.
async fn build_node(signer: Arc<HydeSigner>, roster: Roster) -> Result<(Router, TaskGuard)> {
    let verifier = Arc::new(HydeVerifier::new(roster));
    let (hook, protocol, task) = mutual(signer, verifier);
    let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
    // Spawning also publishes this endpoint's id to the acceptor side.
    let guard = task.spawn(endpoint.clone());
    let router = Router::builder(endpoint)
        .accept(MUTUAL_ALPN, protocol)
        .accept(echo::ALPN, echo::Echo)
        .spawn();
    Ok((router, guard))
}

mod echo {
    //! A bare-bones echo protocol with no knowledge of auth whatsoever.

    use iroh::{
        endpoint::Connection,
        protocol::{AcceptError, ProtocolHandler},
        Endpoint, EndpointAddr,
    };

    pub const ALPN: &[u8] = b"iroh-hyde-auth-example/echo/0";

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
