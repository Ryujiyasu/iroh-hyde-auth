# iroh-hyde-auth

Institutional, **hardware-bound** authentication for [iroh] connections — put a
TPM-backed institutional identity in front of any iroh protocol without that
protocol knowing anything about it.

It follows the structure of iroh's [`auth-hook`] example, but replaces the
example's shared-secret token with a **challenge–response signed by [hyde]**
(ML-DSA / FIPS 204, with the signing seed sealed to a TPM).

> Status: **v0.1, prototype.** Core handshake + offline crypto tests are in
> place. See [Limitations](#limitations).

## Why

Two machines that talk over iroh have a *transport* identity: an in-memory
ephemeral `SecretKey`. That is great for fast handshakes and free rotation, but
it is not an *institutional* identity — a `SecretKey` sitting on disk can be
stolen from a backup, a decommissioned disk, or via root escalation, and then
used to impersonate the institution.

For workloads like multi-institution threshold-FHE (hospital ↔ hospital), peers
need to prove **"this transport session is operated by institution X"**, where
X's key cannot leave the hardware. `iroh-hyde-auth` provides that as a layer
*beside* the application protocol.

## Design

Two identities, kept separate:

| | Transport identity | Institutional identity |
|---|---|---|
| Key | ephemeral in-memory `SecretKey` | TPM-bound ML-DSA (via hyde) |
| Speed | fast handshake, free to rotate | ~10–100 ms signature |
| Exchanged on | every connection | the auth ALPN, once per peer |

The institutional signature is bound to the **ephemeral endpoint id** of the
session. iroh's QUIC/TLS handshake already proves the peer holds the secret key
for that endpoint id, so binding the institutional assertion to it means a relay
or man-in-the-middle cannot reuse a captured assertion for a session it does not
control.

```mermaid
sequenceDiagram
    participant I as Initiator
    participant A as Acceptor
    Note over I,A: separate auth ALPN, the application protocol is untouched
    I->>A: ClientHello
    A->>I: ServerChallenge with nonce and time
    Note over I: transcript = DOMAIN + ver + nonce + my_endpoint_id + time
    Note over I: sig = hyde sign of transcript, on the TPM
    I->>A: ClientAuth with verifying_key, sig, time
    Note over A: rebuild transcript with the QUIC-authenticated remote_id
    Note over A: verify sig and roster membership
    A-->>I: close 1 accepted or 403 denied
    Note over I,A: later the application connects
    Note over I,A: after_handshake admits only pre-authenticated peers
```

The plumbing maps onto iroh's [`EndpointHooks`]:

- **Initiator** — `before_connect` runs the auth handshake before the first
  application dial to a peer (cached per remote afterwards).
- **Acceptor** — `after_handshake` rejects application connections from peers
  that have not authenticated; the `AuthProtocol` (mounted on the auth ALPN)
  runs the challenge–response and records who passed.

## Usage

```toml
[dependencies]
iroh-hyde-auth = { git = "https://github.com/Ryujiyasu/iroh-hyde-auth" }
```

Acceptor:

```rust,ignore
let verifier = Arc::new(HydeVerifier::new(roster));     // roster of trusted institutional keys
let (hook, auth_protocol) = incoming(verifier);
let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
let router = Router::builder(endpoint)
    .accept(iroh_hyde_auth::ALPN, auth_protocol)
    .accept(b"my-app/0", my_protocol)
    .spawn();
```

Initiator:

```rust,ignore
let signer = Arc::new(HydeSigner::generate(FallbackPolicy::Deny)?);  // TPM-bound; Deny = no software fallback
let (hook, task) = outgoing(signer);
let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
let _guard = task.spawn(endpoint.clone());
// any non-auth connection now authenticates transparently first
```

Full, compile-checked run: [`examples/echo-auth.rs`](examples/echo-auth.rs).

### Mutual auth

For peer-to-peer trust (hospital ↔ hospital), use `mutual()`: a single auth-ALPN
exchange has *both* sides prove and verify each other (with role separation to
block reflection), and one combined hook gates connections in both directions.
Each endpoint carries its own signer **and** a roster.

```rust,ignore
let (hook, protocol, task) = mutual(my_signer, my_verifier);
let endpoint = Endpoint::builder(presets::N0).hooks(hook).bind().await?;
let _guard = task.spawn(endpoint.clone());   // also publishes our id to the acceptor side
let router = Router::builder(endpoint)
    .accept(iroh_hyde_auth::MUTUAL_ALPN, protocol)
    .accept(b"my-app/0", my_protocol)
    .spawn();
```

Full run: [`examples/mutual-echo.rs`](examples/mutual-echo.rs).

## Backends & features

- `tpm` *(default)* — institutional key sealed to a TPM 2.0 via hyde. Use
  `FallbackPolicy::Deny` so a missing TPM is a hard error, never a silent
  downgrade.
- `software` — software-backed key, **for development/CI/offline tests only**.

```text
# offline tests: crypto core + real loopback end-to-end (no TPM, no network)
cargo test --no-default-features --features software

# live demos (need network for the n0 preset)
cargo run --example echo-auth   --features software   # one-directional
cargo run --example mutual-echo --features software   # mutual
```

## Security properties

- **Replay-resistant** — each assertion is bound to a fresh acceptor nonce.
- **Session-bound** — bound to the QUIC-authenticated endpoint id, so a relay
  cannot reuse a captured assertion.
- **Hardware-bound** — the institutional private key never leaves the TPM.
- **Post-quantum** — ML-DSA-65 (NIST category 3) signatures.
- **Protocol-agnostic** — the application protocol needs zero changes.

## Limitations

- Two modes ship: one-directional (`incoming`/`outgoing` — initiator proves to
  acceptor) and mutual (`mutual` — both prove and verify). Both are exercised by
  `tests/e2e.rs` over real loopback endpoints (relay + discovery disabled); not
  yet validated across a real n0 relay/NAT-traversal network.
- Roster is an in-memory allow-list; revocation = remove the key. External
  revocation/time-validity sources are not wired in yet.
- The institutional signature runs synchronously on the async task; at high
  connection rates a TPM sign (~10–100 ms) should move to `spawn_blocking`.
- Pinned to `iroh = =1.0.0-rc.1`.

## Relationship to upstream iroh

This is an external crate, not an upstream change. It is the working reference
implementation discussed in [n0-computer/iroh#4221]. No changes to iroh,
iroh-blobs, or iroh-gossip are required — `EndpointHooks::before_connect` plus a
separate ALPN cover it entirely.

## License

MIT © Ryuji Yasukochi

[iroh]: https://docs.rs/iroh
[hyde]: https://gitlab.com/Ryujiyasu/hyde
[`auth-hook`]: https://github.com/n0-computer/iroh/blob/main/iroh/examples/auth-hook.rs
[`EndpointHooks`]: https://docs.rs/iroh/1.0.0-rc.1/iroh/endpoint/trait.EndpointHooks.html
[n0-computer/iroh#4221]: https://github.com/n0-computer/iroh/discussions/4221
