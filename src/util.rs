//! Small internal helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;

/// Current wall-clock time as whole seconds since the Unix epoch.
///
/// Used as an *optional* freshness marker inside the signed transcript; the
/// random challenge nonce is the primary anti-replay mechanism.
pub(crate) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A guard that aborts its background task when dropped.
///
/// Returned by [`crate::OutgoingAuthTask::spawn`]; keep it alive for as long as
/// you want the endpoint to be able to pre-authenticate outgoing connections.
#[derive(Debug)]
pub struct TaskGuard(JoinHandle<()>);

impl TaskGuard {
    pub(crate) fn new(handle: JoinHandle<()>) -> Self {
        Self(handle)
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
