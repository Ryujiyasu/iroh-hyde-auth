//! Tests for the `ssh-agent` backend against a real, throwaway agent.
//!
//! Proves the institutional signer/verifier traits are backend-agnostic: the
//! exact same hooks, roster, and wire protocol run with ed25519-over-ssh-agent
//! instead of TPM-bound ML-DSA.
//!
//! ```text
//! cargo test --no-default-features --features ssh-agent --test ssh_agent
//! ```
#![cfg(feature = "ssh-agent")]

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command},
    sync::Arc,
    time::Duration,
};

use iroh::{
    endpoint::{presets, EndpointHooks},
    protocol::Router,
    Endpoint, EndpointAddr, RelayMode,
};
use iroh_hyde_auth::{
    incoming, outgoing, InstitutionVerifier, InstitutionalSigner, Roster, SshAgentSigner,
    SshVerifier,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxErr>;

/// A throwaway `ssh-agent` with a freshly generated ed25519 key loaded.
struct TestAgent {
    child: Child,
    dir: PathBuf,
    sock: PathBuf,
}

impl TestAgent {
    fn start(tag: &str) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("iha-ssh-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let sock = dir.join("agent.sock");
        let key = dir.join("id_ed25519");

        let ok = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&key)
            .status()?
            .success();
        if !ok {
            return Err("ssh-keygen failed".into());
        }

        // Foreground (-D) so we own the process and can kill it on drop.
        let child = Command::new("ssh-agent").arg("-D").arg("-a").arg(&sock).spawn()?;

        // Wait for the socket to appear.
        let mut ready = false;
        for _ in 0..100 {
            if sock.exists() {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !ready {
            return Err("ssh-agent socket never appeared".into());
        }

        let ok = Command::new("ssh-add")
            .arg(&key)
            .env("SSH_AUTH_SOCK", &sock)
            .status()?
            .success();
        if !ok {
            return Err("ssh-add failed".into());
        }

        Ok(Self { child, dir, sock })
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn ssh_backend_sign_and_verify() -> Result<()> {
    let agent = TestAgent::start("roundtrip")?;
    let signer = SshAgentSigner::connect(&agent.sock, None)?;
    let vk = signer.verifying_key();
    assert_eq!(vk.len(), 32, "ed25519 public key is 32 bytes");

    let mut roster = Roster::new();
    roster.insert(vk.clone(), "node-a");
    let verifier = SshVerifier::new(roster);

    let msg = b"institutional assertion transcript";
    let sig = signer.sign(msg)?;
    assert_eq!(verifier.verify(&vk, msg, &sig)?, "node-a");

    // Tampered signature rejected.
    let mut bad = sig.clone();
    bad[0] ^= 0xff;
    assert!(verifier.verify(&vk, msg, &bad).is_err());

    // Key not in roster rejected.
    let empty = SshVerifier::new(Roster::new());
    assert!(empty.verify(&vk, msg, &sig).is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_backend_gates_echo_e2e() -> Result<()> {
    let agent = TestAgent::start("e2e")?;
    let signer = Arc::new(SshAgentSigner::connect(&agent.sock, None)?);

    // The acceptor trusts the initiator's ssh key.
    let mut roster = Roster::new();
    roster.insert(signer.verifying_key(), "client");
    let verifier = Arc::new(SshVerifier::new(roster));

    // Acceptor: gate echo behind the ssh-backed auth.
    let (hook_in, auth_protocol) = incoming(verifier);
    let server_ep = bind_loopback(hook_in).await?;
    let server = Router::builder(server_ep)
        .accept(iroh_hyde_auth::ALPN, auth_protocol)
        .accept(echo::ALPN, echo::Echo)
        .spawn();

    // Initiator: authenticate outgoing connections with the ssh key.
    let (hook_out, task) = outgoing(signer);
    let client_ep = bind_loopback(hook_out).await?;
    let _guard = task.spawn(client_ep.clone());

    let addr = full_addr(server.endpoint());
    let resp = tokio::time::timeout(
        Duration::from_secs(15),
        echo::Echo::connect(&client_ep, addr, b"hello over ssh"),
    )
    .await
    .map_err(|_| -> BoxErr { "timed out".into() })??;
    assert_eq!(resp, b"hello over ssh");

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
