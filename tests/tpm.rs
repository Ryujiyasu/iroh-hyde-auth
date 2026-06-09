//! TPM-backend tests. These exercise hyde's real TPM 2.0 path (tss-esapi:
//! primary key, seal/unseal of the ML-DSA seed, signing), not the software
//! fallback — `FallbackPolicy::Deny` makes a missing TPM a hard error.
//!
//! Needs a reachable TPM. With a software TPM:
//!
//! ```text
//! swtpm socket --tpm2 --tpmstate dir=/tmp/iha-swtpm \
//!   --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags startup-clear &
//! cargo test --test tpm        # default features include `tpm`
//! ```
#![cfg(feature = "tpm")]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh::{
    endpoint::{presets, EndpointHooks},
    protocol::Router,
    Endpoint, EndpointAddr, RelayMode,
};
use iroh_hyde_auth::{
    incoming, outgoing, FallbackPolicy, HydeSigner, HydeVerifier, InstitutionVerifier,
    InstitutionalSigner, Roster,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxErr>;

/// A single TPM-backed signer: first a direct sign/verify roundtrip, then a
/// full one-directional echo handshake over loopback. One signer (one primary
/// key) so it neither collides with itself nor needs a multi-connection TPM.
/// The acceptor only verifies (no TEE), so a single TPM context is involved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tpm_signs_and_gates_echo() -> Result<()> {
    // Deny => must use the TPM; no software fallback.
    let signer = HydeSigner::generate(FallbackPolicy::Deny)?;
    let vk = signer.verifying_key();

    // Direct sign/verify on the TPM-held key.
    let mut roster = Roster::new();
    roster.insert(vk.clone(), "clinic");
    {
        let verifier = HydeVerifier::new(roster.clone());
        let msg = b"tpm-backed institutional assertion";
        let sig = signer.sign(msg)?;
        assert_eq!(
            verifier.verify(&vk, msg, &sig).map_err(|e| e.to_string())?,
            "clinic"
        );
        let mut bad = sig.clone();
        bad[0] ^= 0xff;
        assert!(verifier.verify(&vk, msg, &bad).is_err());
    }

    // Same signer now gates an echo connection end-to-end.
    let signer = Arc::new(signer);
    let verifier = Arc::new(HydeVerifier::new(roster));

    let (hook_in, auth_protocol) = incoming(verifier);
    let server_ep = bind_loopback(hook_in).await?;
    let server = Router::builder(server_ep)
        .accept(iroh_hyde_auth::ALPN, auth_protocol)
        .accept(echo::ALPN, echo::Echo)
        .spawn();

    let (hook_out, task) = outgoing(signer);
    let client_ep = bind_loopback(hook_out).await?;
    let _guard = task.spawn(client_ep.clone());

    let addr = full_addr(server.endpoint());
    let resp = tokio::time::timeout(
        Duration::from_secs(20),
        echo::Echo::connect(&client_ep, addr, b"hello from the TPM"),
    )
    .await
    .map_err(|_| -> BoxErr { "timed out".into() })??;
    assert_eq!(resp, b"hello from the TPM");

    server.shutdown().await?;
    Ok(())
}

async fn bind_loopback<H: EndpointHooks + 'static>(hook: H) -> Result<Endpoint> {
    Ok(Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())?
        .hooks(hook)
        .bind()
        .await?)
}

fn full_addr(ep: &Endpoint) -> EndpointAddr {
    let mut addr = EndpointAddr::new(ep.id());
    for sock in ep.bound_sockets() {
        if sock.ip().is_loopback() {
            addr = addr.with_ip_addr(sock);
        }
    }
    addr
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
