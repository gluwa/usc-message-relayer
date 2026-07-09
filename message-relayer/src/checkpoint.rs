//! Persistent per-watcher block cursors.
//!
//! Both the Outbox watcher (source chain `MessagePublished`) and the acknowledgment watcher
//! (destination chain `MessageDelivered`) scan chain logs by block range. Without persistence they
//! start from the chain head on every boot, so any event emitted while the relayer was down is
//! silently skipped. This store records the last block each watcher has fully processed and is
//! consulted on startup, so a restart resumes from `last_processed + 1` instead of the head — the
//! relayer never misses an on-chain event, even across downtime.
//!
//! Storage is a single JSON file (`{ "outbox:2": 1234, "ack:2": 5678 }`) written atomically
//! (temp file + rename) so a crash mid-write cannot corrupt it. Reprocessing the tail of a range
//! after an unclean shutdown is safe: delivery is idempotent (`MessageAlreadyValidated`) and acks
//! are deduped + idempotent (`MessageAlreadyAcknowledged`), so the cursor gives at-least-once,
//! never at-most-once.
//!
//! Note: this covers durable *on-chain* events. Attestor votes travel over gossip (ephemeral) and
//! are out of scope here — a relayer that was down while votes were gossiped relies on the votes
//! being re-observed, not on this cursor.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};

/// A JSON-file-backed map of `watcher key -> last fully-processed block`.
#[derive(Debug)]
pub struct CheckpointStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, u64>>,
}

impl CheckpointStore {
    /// Load the store from `path`, treating a missing file as an empty store.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let inner: HashMap<String, u64> = match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => HashMap::new(),
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("parsing checkpoint file {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("reading checkpoint file {}", path.display()))
            }
        };
        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    /// The last fully-processed block for `key`, if any has been recorded.
    pub fn get(&self, key: &str) -> Option<u64> {
        self.inner
            .lock()
            .expect("checkpoint mutex")
            .get(key)
            .copied()
    }

    /// Record `block` as the last fully-processed block for `key` and persist the whole store.
    ///
    /// The lock is held across the file write so concurrent watchers cannot interleave a stale
    /// snapshot over a newer one; writes are small and infrequent (one per poll tick).
    pub fn set(&self, key: &str, block: u64) -> Result<()> {
        let mut guard = self.inner.lock().expect("checkpoint mutex");
        guard.insert(key.to_string(), block);
        let serialized =
            serde_json::to_string_pretty(&*guard).context("serializing checkpoint store")?;
        write_atomic(&self.path, serialized.as_bytes())
    }
}

/// Cross-task cursor holdback for the Outbox watchers (per `chain_key`).
///
/// The Outbox checkpoint is written by the watcher, but "is this message finished?" is pool state —
/// a message can sit undelivered (below quorum, or destination down) long after the scan cursor
/// passed its block. Persisting the raw cursor therefore loses undelivered messages across a
/// restart once they age out of the fixed lookback window: the rescan no longer reaches them, stray
/// votes are dropped by the chain-first allowlist, and no reobservation is ever requested. The pool
/// publishes the oldest unfinished (undelivered, non-terminal) message block per route here on its
/// prune tick; the watcher clamps the *persisted* cursor to `oldest - 1` so a restart always
/// re-indexes every unfinished message. The in-memory cursor is not clamped — the live scan never
/// re-reads.
#[derive(Debug, Default)]
pub struct CursorHoldback {
    /// `chain_key` → oldest unfinished message block (`None` = route has no unfinished messages).
    oldest: Mutex<HashMap<u64, Option<u64>>>,
}

impl CursorHoldback {
    /// Publish the oldest unfinished block for `chain_key` (`None` clears the holdback).
    pub fn update(&self, chain_key: u64, oldest_block: Option<u64>) {
        self.oldest
            .lock()
            .expect("holdback mutex")
            .insert(chain_key, oldest_block);
    }

    /// Clamp `cursor` so it does not advance past the oldest unfinished block for `chain_key`.
    /// Identity when the route has no unfinished messages (or has not reported yet).
    pub fn clamp(&self, chain_key: u64, cursor: u64) -> u64 {
        match self
            .oldest
            .lock()
            .expect("holdback mutex")
            .get(&chain_key)
            .copied()
            .flatten()
        {
            Some(oldest) => cursor.min(oldest.saturating_sub(1)),
            None => cursor,
        }
    }
}

/// Write `bytes` to `path` atomically via a sibling temp file + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating checkpoint dir {}", parent.display()))?;
        }
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .with_context(|| format!("writing checkpoint temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming checkpoint temp file into {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cp.json");

        let store = CheckpointStore::load(&path).unwrap();
        assert_eq!(store.get("outbox:2"), None);
        store.set("outbox:2", 100).unwrap();
        store.set("ack:2", 250).unwrap();
        store.set("outbox:2", 150).unwrap(); // overwrite advances

        // A fresh load sees the persisted cursors.
        let reloaded = CheckpointStore::load(&path).unwrap();
        assert_eq!(reloaded.get("outbox:2"), Some(150));
        assert_eq!(reloaded.get("ack:2"), Some(250));
        assert_eq!(reloaded.get("missing"), None);
    }

    #[test]
    fn holdback_clamps_only_when_unfinished_work_reported() {
        let hb = CursorHoldback::default();
        // Unreported route: identity.
        assert_eq!(hb.clamp(2, 1000), 1000);
        // Unfinished message at block 400 → cursor pinned to 399.
        hb.update(2, Some(400));
        assert_eq!(hb.clamp(2, 1000), 399);
        // A cursor already below the holdback is untouched.
        assert_eq!(hb.clamp(2, 300), 300);
        // Another route is independent.
        assert_eq!(hb.clamp(7, 1000), 1000);
        // Clearing (all delivered/terminal) releases the cursor.
        hb.update(2, None);
        assert_eq!(hb.clamp(2, 1000), 1000);
    }

    #[test]
    fn missing_file_is_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("cp.json");
        let store = CheckpointStore::load(&path).unwrap();
        assert_eq!(store.get("anything"), None);
        // First write creates the nested dir.
        store.set("ack:7", 42).unwrap();
        assert_eq!(CheckpointStore::load(&path).unwrap().get("ack:7"), Some(42));
    }
}
