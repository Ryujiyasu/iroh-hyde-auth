//! A second institutional backend, backed by a running `ssh-agent`.
//!
//! This exists to validate that [`InstitutionalSigner`] / [`InstitutionVerifier`]
//! are genuinely backend-agnostic: the wire protocol, hooks, roster, and
//! transcript binding are all unchanged — only the signature scheme differs
//! (ed25519 via the agent instead of TPM-bound ML-DSA via hyde).
//!
//! The agent holds the private key; signing is a request over `SSH_AUTH_SOCK`.
//! The institutional "verifying key" is the raw 32-byte ed25519 public key, and
//! the [`Roster`] maps those to labels exactly as with the hyde backend.
//!
//! Unix only (the agent is reached over a Unix-domain socket).
//!
//! [`InstitutionalSigner`]: crate::InstitutionalSigner
//! [`InstitutionVerifier`]: crate::InstitutionVerifier

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    error::{Error, Result},
    signer::InstitutionalSigner,
    verifier::{InstitutionId, InstitutionVerifier, Roster, VerifyError},
};

// ssh-agent protocol message numbers (OpenSSH PROTOCOL.agent).
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

const ED25519_KEY_TYPE: &[u8] = b"ssh-ed25519";
const MAX_AGENT_MSG: usize = 1 << 20;

/// An [`InstitutionalSigner`] that signs via a running `ssh-agent`.
///
/// The selected key must be an ed25519 key already loaded in the agent.
#[derive(Debug, Clone)]
pub struct SshAgentSigner {
    sock: PathBuf,
    /// The full ssh key blob (`string "ssh-ed25519" || string pubkey`).
    key_blob: Vec<u8>,
    /// The raw 32-byte ed25519 public key — the institutional verifying key.
    public_key: [u8; 32],
}

impl SshAgentSigner {
    /// Connect to the agent at `$SSH_AUTH_SOCK` and use its first ed25519 key.
    pub fn from_env() -> Result<Self> {
        let sock = std::env::var_os("SSH_AUTH_SOCK")
            .ok_or_else(|| Error::Signer("SSH_AUTH_SOCK is not set".into()))?;
        Self::connect(PathBuf::from(sock), None)
    }

    /// Connect to the agent at `sock`. If `want_public_key` is given, select that
    /// exact ed25519 key; otherwise use the first ed25519 key the agent lists.
    pub fn connect(sock: impl Into<PathBuf>, want_public_key: Option<[u8; 32]>) -> Result<Self> {
        let sock = sock.into();
        let mut stream = connect(&sock)?;

        send(&mut stream, &[REQUEST_IDENTITIES])?;
        let resp = recv(&mut stream)?;
        let mut r = Reader::new(&resp);
        if r.u8()? != IDENTITIES_ANSWER {
            return Err(Error::Signer("ssh-agent: unexpected identities reply".into()));
        }
        let count = r.u32()?;
        for _ in 0..count {
            let key_blob = r.string()?;
            let _comment = r.string()?;
            if let Some(pk) = parse_ed25519_public_key(key_blob) {
                if want_public_key.map(|w| w == pk).unwrap_or(true) {
                    return Ok(Self {
                        sock,
                        key_blob: key_blob.to_vec(),
                        public_key: pk,
                    });
                }
            }
        }
        Err(Error::Signer(
            "ssh-agent: no matching ed25519 identity loaded".into(),
        ))
    }
}

impl InstitutionalSigner for SshAgentSigner {
    fn verifying_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut stream = connect(&self.sock)?;

        let mut payload = vec![SIGN_REQUEST];
        put_string(&mut payload, &self.key_blob);
        put_string(&mut payload, message);
        payload.extend_from_slice(&0u32.to_be_bytes()); // flags: 0 for ed25519
        send(&mut stream, &payload)?;

        let resp = recv(&mut stream)?;
        let mut r = Reader::new(&resp);
        if r.u8()? != SIGN_RESPONSE {
            return Err(Error::Signer("ssh-agent: signing was refused".into()));
        }
        // signature := string( string "ssh-ed25519" || string raw_sig )
        let sig_blob = r.string()?;
        let mut sr = Reader::new(sig_blob);
        let sig_type = sr.string()?;
        if sig_type != ED25519_KEY_TYPE {
            return Err(Error::Signer("ssh-agent: non-ed25519 signature".into()));
        }
        Ok(sr.string()?.to_vec())
    }
}

/// An [`InstitutionVerifier`] for ed25519 institutional keys (the [`SshAgentSigner`]
/// counterpart). Reuses [`Roster`] — only the signature scheme differs.
#[derive(Debug, Clone)]
pub struct SshVerifier {
    roster: Roster,
}

impl SshVerifier {
    /// Verify against the given roster of raw 32-byte ed25519 public keys.
    pub fn new(roster: Roster) -> Self {
        Self { roster }
    }
}

impl InstitutionVerifier for SshVerifier {
    fn verify(
        &self,
        verifying_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<InstitutionId, VerifyError> {
        if !self.roster.contains(verifying_key) {
            return Err(VerifyError::UntrustedKey);
        }
        let vk_bytes: [u8; 32] = verifying_key
            .try_into()
            .map_err(|_| VerifyError::Crypto("ed25519 key must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|e| VerifyError::Crypto(e.to_string()))?;
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| VerifyError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(message, &sig)
            .map_err(|_| VerifyError::BadSignature)?;
        Ok(self.roster.label(verifying_key).unwrap_or_default().to_string())
    }
}

// ---------------------------------------------------------------------------
// ssh-agent wire helpers
// ---------------------------------------------------------------------------

fn connect(sock: &PathBuf) -> Result<UnixStream> {
    UnixStream::connect(sock).map_err(|e| Error::Signer(format!("ssh-agent connect: {e}")))
}

fn send(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| Error::Signer("agent msg too large".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(payload))
        .map_err(|e| Error::Signer(format!("ssh-agent write: {e}")))
}

fn recv(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| Error::Signer(format!("ssh-agent read: {e}")))?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_AGENT_MSG {
        return Err(Error::Signer("ssh-agent: bad message length".into()));
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|e| Error::Signer(format!("ssh-agent read: {e}")))?;
    Ok(buf)
}

fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// `string "ssh-ed25519" || string pubkey(32)` → raw 32-byte public key.
fn parse_ed25519_public_key(key_blob: &[u8]) -> Option<[u8; 32]> {
    let mut r = Reader::new(key_blob);
    let key_type = r.string().ok()?;
    if key_type != ED25519_KEY_TYPE {
        return None;
    }
    let pk = r.string().ok()?;
    pk.try_into().ok()
}

/// Minimal reader for SSH wire encoding (big-endian length-prefixed fields).
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| Error::Signer("ssh-agent: truncated message".into()))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}
