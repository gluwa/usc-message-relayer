//! Progress-aware liveness backing the `/health` endpoint.
//!
//! Previously `/health` was an unconditional `200`, so every mid-run wedge — a silently dead WS
//! provider that stops a watcher indexing, a pool that stops turning — survived indefinitely behind
//! a green check, and k8s only ever restarted the relayer on a full-process exit (which the
//! steady-state loops never produce, since they catch their own errors and retry forever). This
//! module lets each polling worker report *forward progress*; `/health` returns `503` when any
//! registered worker has gone silent past [`PROGRESS_DEADLINE`], so the k8s liveness probe pulls the
//! restart lever that rebuilds providers and resumes from the checkpoint.
//!
//! A worker heartbeats only on a **successful** poll iteration (an `eth_getLogs` scan that returned,
//! a pool prune tick that ran), not merely on the timer firing — otherwise a dead-provider loop that
//! keeps ticking-and-erroring would look alive, which is exactly the wedge we must catch. The
//! deadline is deliberately generous relative to every worker's cadence so a healthy-but-idle
//! relayer is never restarted.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a registered worker may go without reporting progress before `/health` reports the
/// process unhealthy. Generous versus every worker's poll cadence (outbox/ack/claim scan ~6s, pool
/// prune 30s) so a quiet relayer is never killed; short enough that a genuinely wedged worker (dead
/// provider → no successful poll ever again) trips a restart within a few minutes.
pub const PROGRESS_DEADLINE: Duration = Duration::from_secs(5 * 60);

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Shared liveness registry. Workers heartbeat by name; `/health` checks every registered name
/// against [`PROGRESS_DEADLINE`].
#[derive(Debug)]
pub struct Health {
    /// component name → unix-millis of its last reported progress.
    components: Mutex<HashMap<String, u64>>,
    deadline_ms: u64,
}

impl Health {
    #[must_use]
    pub fn new(deadline: Duration) -> Arc<Self> {
        Arc::new(Self {
            components: Mutex::new(HashMap::new()),
            deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Report forward progress for `name`, registering it on first call. Workers call this once at
    /// startup (so a worker that wedges before its first successful poll still goes stale and trips
    /// a restart) and again after every successful poll iteration.
    pub fn heartbeat(&self, name: &str) {
        let now = now_unix_ms();
        let mut guard = self.components.lock().expect("health mutex poisoned");
        if let Some(ts) = guard.get_mut(name) {
            *ts = now;
        } else {
            guard.insert(name.to_owned(), now);
        }
    }

    /// `(alive, stale_components)`. Alive iff every registered worker has reported within the
    /// deadline. The stale list is returned so `/health` can name the wedged worker in its body.
    #[must_use]
    pub fn status(&self) -> (bool, Vec<String>) {
        let now = now_unix_ms();
        let guard = self.components.lock().expect("health mutex poisoned");
        let mut stale: Vec<String> = guard
            .iter()
            .filter(|(_, &ts)| now.saturating_sub(ts) > self.deadline_ms)
            .map(|(name, _)| name.clone())
            .collect();
        stale.sort();
        (stale.is_empty(), stale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_is_alive() {
        let h = Health::new(PROGRESS_DEADLINE);
        assert_eq!(h.status(), (true, Vec::new()));
    }

    #[test]
    fn fresh_heartbeat_is_alive() {
        let h = Health::new(PROGRESS_DEADLINE);
        h.heartbeat("outbox:2");
        let (alive, stale) = h.status();
        assert!(alive);
        assert!(stale.is_empty());
    }

    #[test]
    fn stale_component_reports_unhealthy() {
        let h = Health::new(Duration::from_secs(5 * 60));
        {
            let mut g = h.components.lock().unwrap();
            // One worker went silent 10 minutes ago (past the 5-minute deadline), one is current.
            g.insert(
                "outbox:2".to_owned(),
                now_unix_ms().saturating_sub(10 * 60 * 1000),
            );
            g.insert("pool".to_owned(), now_unix_ms());
        }
        let (alive, stale) = h.status();
        assert!(!alive);
        assert_eq!(stale, vec!["outbox:2".to_owned()]);
    }
}
