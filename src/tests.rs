//! Offline tests for the crypto core: signer + verifier + transcript binding.
//!
//! These run without any networking by exercising the institutional handshake's
//! security-critical pieces directly. They need the `software` backend so a key
//! can be generated without a TPM:
//!
//! ```text
//! cargo test --no-default-features --features software
//! ```
#![cfg(feature = "software")]

use crate::{
    wire::{transcript, ENDPOINT_ID_LEN, NONCE_LEN},
    FallbackPolicy, HydeSigner, HydeVerifier, InstitutionVerifier, InstitutionalSigner, Roster,
    VerifyError,
};

const TS: u64 = 1_700_000_000;

fn signer() -> HydeSigner {
    HydeSigner::generate(FallbackPolicy::Software).expect("software signer")
}

fn roster_with(vk: &[u8], label: &str) -> Roster {
    let mut r = Roster::new();
    r.insert(vk.to_vec(), label);
    r
}

#[test]
fn valid_assertion_verifies() {
    let s = signer();
    let vk = s.verifying_key();
    let verifier = HydeVerifier::new(roster_with(&vk, "hospital-a"));

    let nonce = [0x11; NONCE_LEN];
    let id = [0x22; ENDPOINT_ID_LEN];
    let msg = transcript(&nonce, &id, TS);
    let sig = s.sign(&msg).unwrap();

    let who = verifier.verify(&vk, &msg, &sig).expect("should verify");
    assert_eq!(who, "hospital-a");
}

#[test]
fn tampered_signature_rejected() {
    let s = signer();
    let vk = s.verifying_key();
    let verifier = HydeVerifier::new(roster_with(&vk, "hospital-a"));

    let nonce = [0x11; NONCE_LEN];
    let id = [0x22; ENDPOINT_ID_LEN];
    let msg = transcript(&nonce, &id, TS);
    let mut sig = s.sign(&msg).unwrap();
    sig[0] ^= 0xff;

    assert!(matches!(
        verifier.verify(&vk, &msg, &sig),
        Err(VerifyError::BadSignature)
    ));
}

#[test]
fn key_not_in_roster_rejected() {
    let s = signer();
    let vk = s.verifying_key();
    // Empty roster: nobody is trusted.
    let verifier = HydeVerifier::new(Roster::new());

    let nonce = [0x11; NONCE_LEN];
    let id = [0x22; ENDPOINT_ID_LEN];
    let msg = transcript(&nonce, &id, TS);
    let sig = s.sign(&msg).unwrap();

    assert!(matches!(
        verifier.verify(&vk, &msg, &sig),
        Err(VerifyError::UntrustedKey)
    ));
}

#[test]
fn different_institution_not_admitted() {
    let trusted = signer();
    let attacker = signer();
    // Roster trusts only `trusted`'s key.
    let verifier = HydeVerifier::new(roster_with(&trusted.verifying_key(), "hospital-a"));

    let nonce = [0x11; NONCE_LEN];
    let id = [0x22; ENDPOINT_ID_LEN];
    let msg = transcript(&nonce, &id, TS);
    let sig = attacker.sign(&msg).unwrap();

    assert!(matches!(
        verifier.verify(&attacker.verifying_key(), &msg, &sig),
        Err(VerifyError::UntrustedKey)
    ));
}

#[test]
fn endpoint_id_binding_enforced() {
    // The initiator signs an assertion bound to its own endpoint id. If a relay
    // replays that assertion on a connection from a *different* endpoint id, the
    // acceptor rebuilds the transcript with the real remote id and verification
    // must fail.
    let s = signer();
    let vk = s.verifying_key();
    let verifier = HydeVerifier::new(roster_with(&vk, "hospital-a"));

    let nonce = [0x11; NONCE_LEN];
    let honest_id = [0x22; ENDPOINT_ID_LEN];
    let relay_id = [0x33; ENDPOINT_ID_LEN];

    let signed = transcript(&nonce, &honest_id, TS);
    let sig = s.sign(&signed).unwrap();

    // Acceptor sees the connection coming from `relay_id`.
    let as_seen = transcript(&nonce, &relay_id, TS);
    assert!(matches!(
        verifier.verify(&vk, &as_seen, &sig),
        Err(VerifyError::BadSignature)
    ));
}

#[test]
fn nonce_binding_enforced() {
    // A signature for one challenge nonce must not verify under another.
    let s = signer();
    let vk = s.verifying_key();
    let verifier = HydeVerifier::new(roster_with(&vk, "hospital-a"));

    let id = [0x22; ENDPOINT_ID_LEN];
    let signed = transcript(&[0x11; NONCE_LEN], &id, TS);
    let sig = s.sign(&signed).unwrap();

    let other = transcript(&[0xAB; NONCE_LEN], &id, TS);
    assert!(matches!(
        verifier.verify(&vk, &other, &sig),
        Err(VerifyError::BadSignature)
    ));
}
