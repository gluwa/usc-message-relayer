//! Signer-serialized transaction broadcasting.
//!
//! Every worker that *sends* transactions shares this module's two halves, which are only correct
//! together:
//!
//!  * [`chain_nonce_builder`] — a provider whose nonce is read from the chain on every send instead
//!    of from a local counter.
//!  * [`BroadcastLocks`] — a process-wide lock keyed by signer address, held across the nonce read
//!    *and* the broadcast, so concurrent senders on one key cannot read the same pending count.
//!
//! # The failure this fixes
//!
//! `ProviderBuilder::new()`'s recommended fillers include a `NonceFiller<CachedNonceManager>`,
//! which reads the nonce from the chain once and then increments a local counter. It advances that
//! counter during `prepare`, i.e. **before** the broadcast. So any send that fails after prepare —
//! an RPC 502, a `eth_sendRawTransaction` timeout, a load-balancer failover, a `SEND_TIMEOUT`
//! abandonment — consumes a nonce that never reached the mempool. Every later transaction from that
//! signer is then signed one past the chain's pending count: the node accepts it and it simply never
//! mines. The route makes no further progress, and because the counter only re-reads the chain when
//! a fresh provider is built, nothing short of a process restart clears it.
//!
//! Reading the nonce from the chain per send removes the gap: a broadcast that never landed leaves
//! the pending count untouched, so the next attempt re-reads the same nonce and retries cleanly.
//!
//! # Why the lock is not optional
//!
//! Chain-read nonces alone are a *regression*, which is why the first attempt at this fix was
//! reverted (see the git history for `SimpleNonceManager`). `ack` and `claim` each fan out
//! `MAX_{ACK,CLAIM}_CONCURRENCY` sends over one wallet provider. `CachedNonceManager` holds its
//! mutex across fetch-and-increment, so those concurrent sends got distinct nonces from the local
//! counter. `SimpleNonceManager` is a stateless unit struct: all of them would read the same pending
//! count before any of them broadcast, and all but one would fail as `nonce too low` — which
//! `is_revert` does not match, so they backoff-retry, collapsing throughput.
//!
//! [`BroadcastLocks`] restores that coordination without the local counter, and extends it further
//! than the cached manager ever reached. The cached manager's mutex is per-provider, so it only
//! coordinated senders sharing one provider instance; workers that share a signer key across routes
//! and roles (delivery and set-update use `route.signer_key`; several routes may configure the same
//! Creditcoin key for `ack`/`claim`) each had an independent counter and collided with each other.
//! This registry is keyed by signer address and shared process-wide, so every sender on one key
//! serializes regardless of which worker or provider it belongs to.
//!
//! # The invariant
//!
//! The guard covers the nonce read and the broadcast, and **nothing else**. It must never be held
//! across a receipt wait: a broadcast is one round trip, whereas a receipt is up to
//! `RECEIPT_TIMEOUT`, and holding the key for that long would serialize whole confirmations and
//! collapse the fan-out this exists to protect. [`BroadcastLocks::broadcast`] enforces the
//! boundary by construction — it takes only the send future and releases before returning, so the
//! caller cannot accidentally extend the critical section.
//!
//! # Costs and residual hazards, stated because they are not obvious
//!
//!  * **The guard spans more than the broadcast.** `send()` is one opaque future covering gas, fee,
//!    nonce and `eth_sendRawTransaction`, so serializing it serializes ~4 round trips per send, not
//!    one. That is a real throughput cost where sends fan out: `ack` and `claim` push
//!    `MAX_{ACK,CLAIM}_CONCURRENCY` (8) sends per tick that previously overlapped fully and now
//!    queue. Correctness first — but if a backlog stops draining within its tick, the fix is to
//!    fill gas and fee *outside* the guard (they need no ordering) and hold it for only the nonce
//!    read and the broadcast. That means staging a `TransactionRequest` by hand instead of using the
//!    typed `CallBuilder`, which also moves the error surface that revert classification reads —
//!    worth measuring before paying for.
//!  * **Load-balanced RPC.** The nonce read and the broadcast may land on different nodes behind one
//!    endpoint. If the read hits a node whose mempool has not yet seen the previous broadcast, two
//!    txs get the same nonce and one fails as a duplicate. That is a retryable error rather than a
//!    permanent gap, so it degrades far better than the cached-counter wedge, but it is why the lock
//!    is held across the broadcast rather than just the read: it shrinks the window to the
//!    propagation delay of a single tx.
//!  * **A genuinely stuck tx.** If a broadcast *is* accepted and then never mines (underpriced), the
//!    pending count legitimately includes it and later sends queue behind it. No nonce management
//!    fixes that — it needs a same-nonce replacement at a higher fee, which is separate work.
//!    `RECEIPT_TIMEOUT` bounds how long a worker waits on one.
//!  * **One extra `eth_getTransactionCount` per send**, replacing a local increment.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use alloy::network::Ethereum;
use alloy::primitives::Address;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, GasFiller, JoinFill, NonceFiller, SimpleNonceManager,
};
use alloy::providers::{Identity, ProviderBuilder};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Upper bound on waiting for a signer's broadcast slot.
///
/// This is an escape hatch, not a normal-path bound: a broadcast is a single round trip, so the
/// queue ahead of any caller drains in well under a second in health. Reaching this timeout means
/// the signer's RPC is pathological, and the caller should fall back to its own retry path rather
/// than park. Bounded at all because an unbounded await here would reintroduce exactly what the
/// per-send timeouts exist to prevent — a worker pinned inside a `select!` branch, unable to observe
/// its cancel token, making SIGTERM a no-op.
pub const QUEUE_TIMEOUT: Duration = Duration::from_secs(120);

/// The filler stack produced by [`chain_nonce_builder`]: alloy's recommended set, but with
/// [`SimpleNonceManager`] in place of the default `CachedNonceManager`.
type ChainNonceFillers = JoinFill<
    JoinFill<
        JoinFill<JoinFill<Identity, GasFiller>, BlobGasFiller>,
        NonceFiller<SimpleNonceManager>,
    >,
    ChainIdFiller,
>;

/// A [`ProviderBuilder`] for signing workers whose nonce is re-read from the chain on every send.
///
/// Must be paired with [`BroadcastLocks`] on the signer's address — see the module docs for why
/// chain-read nonces alone are a regression.
///
/// # Why the stack is composed by hand
///
/// `ProviderBuilder::new()` is `default().with_recommended_fillers()`, and that recommended set
/// already contains a `NonceFiller<CachedNonceManager>`. `with_simple_nonce_management()` calls
/// `self.filler(..)`, which **appends** — there is no replace or prepend — so the obvious spelling
/// `ProviderBuilder::new().with_simple_nonce_management()` leaves *two* nonce fillers in the stack.
/// It does in fact use the simple one (`JoinFill::fill` applies left-then-right and
/// `NonceFiller::fill` calls `set_nonce` unconditionally, so the appended filler wins), but which
/// one wins is an implementation detail of alloy's filler composition that two prior commits here
/// read in opposite directions — first as "the append is a silent no-op", then as "the append
/// works". Composing from `default()` puts exactly one nonce filler in the stack, so there is no
/// precedence question to get wrong, and a future alloy release cannot silently flip the answer.
///
/// # Usage
///
/// ```ignore
/// let provider = chain_nonce_builder()
///     .wallet(wallet)
///     .connect(&rpc_url)
///     .await?;
/// ```
#[must_use]
pub fn chain_nonce_builder() -> ProviderBuilder<Identity, ChainNonceFillers, Ethereum> {
    ProviderBuilder::default()
        .filler(GasFiller::default())
        .filler(BlobGasFiller::default())
        .with_simple_nonce_management()
        .fetch_chain_id()
}

/// Why a serialized broadcast did not complete. Both variants mean "no transaction was signed with
/// a nonce we then failed to use", so a caller may retry without leaving a gap behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stalled {
    /// Never obtained the signer's broadcast slot.
    Queue(Duration),
    /// Held the slot, but the broadcast itself did not return in time. The transaction *may* have
    /// reached the node — callers must treat this as "unknown", not "failed", and rely on
    /// idempotency (a duplicate re-send reverts as already-handled) rather than assuming it landed.
    Broadcast(Duration),
}

impl std::fmt::Display for Stalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queue(d) => write!(f, "no broadcast slot for this signer within {d:?}"),
            Self::Broadcast(d) => write!(f, "broadcast did not complete within {d:?}"),
        }
    }
}

/// Process-wide broadcast serialization, keyed by signer address.
///
/// Cheap to clone via [`Arc`]; construct one in the top-level runtime and hand a clone to every
/// sending worker. Workers that never share a key simply never contend.
#[derive(Debug, Default)]
pub struct BroadcastLocks {
    /// Registry of per-signer locks. The outer `std` mutex guards only the map lookup — it is never
    /// held across an await, so it cannot be the thing that blocks a broadcast. The inner
    /// `tokio` mutex is the broadcast slot itself, and is FIFO-fair, so a busy signer cannot starve
    /// one worker indefinitely.
    locks: StdMutex<HashMap<Address, Arc<Mutex<()>>>>,
}

impl BroadcastLocks {
    /// A fresh registry, ready to share across workers.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Run `send` as the only in-flight broadcast for `signer`, bounded at both stages.
    ///
    /// `send` must be the broadcast alone (alloy's `.send()`), never the receipt wait — see the
    /// module docs. The guard is released before this returns, so the value handed back (typically a
    /// `PendingTransactionBuilder`) is awaited by the caller outside the critical section.
    ///
    /// `Err(`[`Stalled`]`)` means no nonce was consumed on our side and the caller may retry; the
    /// inner `send` result is passed through untouched so existing revert classification still
    /// applies.
    pub async fn broadcast<F>(
        &self,
        signer: Address,
        timeout: Duration,
        send: F,
    ) -> Result<F::Output, Stalled>
    where
        F: Future,
    {
        let slot = self.slot_for(signer);
        let _guard: OwnedMutexGuard<()> =
            match tokio::time::timeout(QUEUE_TIMEOUT, slot.lock_owned()).await {
                Ok(guard) => guard,
                Err(_elapsed) => return Err(Stalled::Queue(QUEUE_TIMEOUT)),
            };
        tokio::time::timeout(timeout, send)
            .await
            .map_err(|_elapsed| Stalled::Broadcast(timeout))
    }

    /// The broadcast slot for `signer`, created on first use.
    fn slot_for(&self, signer: Address) -> Arc<Mutex<()>> {
        let mut locks = self
            .locks
            .lock()
            // The guarded section is a map lookup and an `Arc` clone — neither panics, so the mutex
            // cannot actually be poisoned. Recover rather than propagate anyway: a poisoned registry
            // must not be the reason every sender in the process stops broadcasting.
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(locks.entry(signer).or_default())
    }

    /// How many distinct signers have been seen. Test-only observability.
    #[cfg(test)]
    fn tracked_signers(&self) -> usize {
        self.locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    /// The property the whole fix rests on: two broadcasts on one signer never overlap, so the
    /// second reads a pending nonce that already reflects the first.
    #[tokio::test]
    async fn same_signer_broadcasts_do_not_overlap() {
        let locks = BroadcastLocks::new();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let locks = locks.clone();
            let in_flight = in_flight.clone();
            let max_seen = max_seen.clone();
            tasks.push(tokio::spawn(async move {
                locks
                    .broadcast(addr(1), Duration::from_secs(5), async {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_seen.fetch_max(now, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
                    .expect("broadcast should not stall");
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            1,
            "two broadcasts on one signer overlapped; they would race on the same chain-read nonce"
        );
    }

    /// Distinct signers have independent nonce sequences, so serializing across them would be pure
    /// throughput loss — a held slot on one key must not block another.
    #[tokio::test]
    async fn distinct_signers_do_not_contend() {
        let locks = BroadcastLocks::new();
        let held = locks.slot_for(addr(1)).lock_owned().await;

        let other = locks
            .broadcast(addr(2), Duration::from_secs(5), async { 7 })
            .await;

        assert_eq!(other, Ok(7), "a different signer's slot was blocked");
        drop(held);
        assert_eq!(locks.tracked_signers(), 2);
    }

    /// A caller must not park forever behind a signer whose broadcast is wedged: it needs to fall
    /// back to its own retry path, and its worker needs to reach its cancel branch.
    #[tokio::test(start_paused = true)]
    async fn queue_wait_is_bounded() {
        let locks = BroadcastLocks::new();
        let held = locks.slot_for(addr(1)).lock_owned().await;

        let queued = locks.broadcast(addr(1), Duration::from_secs(5), async { 7 });

        assert_eq!(queued.await, Err(Stalled::Queue(QUEUE_TIMEOUT)));
        drop(held);
    }

    /// A hung broadcast releases the slot instead of wedging every other sender on the key.
    #[tokio::test(start_paused = true)]
    async fn a_hung_broadcast_releases_the_slot() {
        let locks = BroadcastLocks::new();
        let timeout = Duration::from_secs(30);

        let stalled = locks
            .broadcast(addr(1), timeout, std::future::pending::<()>())
            .await;
        assert_eq!(stalled, Err(Stalled::Broadcast(timeout)));

        // The next caller gets the slot immediately rather than queueing behind the hung send.
        let after = locks.broadcast(addr(1), timeout, async { 7 }).await;
        assert_eq!(after, Ok(7));
    }
}
