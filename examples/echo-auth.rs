//! End-to-end demo: an echo protocol gated behind institutional auth.
//!
//! The echo protocol itself knows nothing about authentication. The acceptor
//! only admits echo connections from initiators whose institutional ML-DSA key
//! is in its roster; everyone else is rejected before echo is ever reached.
//!
//! Run (needs a `software` backend so no TPM is required, and network access for
//! the default n0 preset):
//!
//! ```text
//! cargo run --example echo-auth --features software
//! ```

use std::sync::Arc;

use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointAddr};
use iroh_hyde_auth::{
    incoming, outgoing, FallbackPolicy, HydeSigner, HydeVerifier, InstitutionalSigner, Roster,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // The institution that *should* be admitted. In production this key would be
    // generated once and sealed to the initiator's TPM (FallbackPolicy::Deny).
    let hospital_a = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);
    // An institution that is NOT on the acceptor's roster.
    let outsider = Arc::new(HydeSigner::generate(FallbackPolicy::Software)?);

    // The acceptor trusts only hospital A.
    let mut roster = Roster::new();
    roster.insert(hospital_a.verifying_key(), "hospital-a");

    let server = accept_side(roster).await?;
    server.endpoint().online().await;
    let server_addr = server.endpoint().addr();

    println!("-- no auth --");
    match connect_no_auth(server_addr.clone()).await {
        Ok(_) => println!("  UNEXPECTED: echo succeeded without auth"),
        Err(e) => println!("  rejected as expected: {e}"),
    }

    println!("-- wrong institution --");
    match connect_with(server_addr.clone(), outsider).await {
        Ok(_) => println!("  UNEXPECTED: untrusted institution admitted"),
        Err(e) => println!("  rejected as expected: {e}"),
    }

    println!("-- trusted institution --");
    match connect_with(server_addr.clone(), hospital_a).await {
        Ok(resp) => println!("  echo ok: {:?}", String::from_utf8_lossy(&resp)),
        Err(e) => println!("  UNEXPECTED failure: {e}"),
    }

    server.shutdown().await?;
    Ok(())
}

async fn accept_side(roster: Roster) -> Result<Router> {
    let verifier = Arc::new(HydeVerifier::new(roster));
    let (hook, auth_protocol) = incoming(verifier);
    let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
    let router = Router::builder(endpoint)
        .accept(iroh_hyde_auth::ALPN, auth_protocol)
        .accept(echo::ALPN, echo::Echo)
        .spawn();
    Ok(router)
}

async fn connect_with(remote: EndpointAddr, signer: Arc<HydeSigner>) -> Result<Vec<u8>> {
    let (hook, task) = outgoing(signer);
    let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
    let _guard = task.spawn(endpoint.clone());
    echo::Echo::connect(&endpoint, remote, b"hello from the clinic").await
}

async fn connect_no_auth(remote: EndpointAddr) -> Result<Vec<u8>> {
    let endpoint = Endpoint::bind(presets::N0).await?;
    echo::Echo::connect(&endpoint, remote, b"hello from the clinic").await
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
