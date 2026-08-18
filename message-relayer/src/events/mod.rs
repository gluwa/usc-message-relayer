//! Outbox event discovery.
//!
//! For every configured route, this module spawns a poller that watches the Creditcoin L1 EVM
//! endpoint for `MessagePublished` events on the route's resolved Outbox. New events become
//! [`IndexedMessage`]s pushed into the shared vote pool — the **chain-first allowlist** of PoC
//! §6.2: votes for `messageHash`es we have not indexed are dropped on arrival.

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::abi::IOutbox;
use crate::checkpoint::CheckpointStore;
use crate::config::ChainRoute;
use crate::hash::message_hash;
use crate::prom::Metrics;
use write_ability::protocol::chain_key_to_bytes32;

pub mod factory;

pub use factory::{ConfigOverrideResolver, FactoryResolver, OutboxResolver, ResolvedOutbox};

/// Default poll cadence for re-checking whether [`OutboxResolver::resolve`] now returns a
/// different address (an Outbox rotation). Independent of, and much slower than,
/// [`DEFAULT_POLL_INTERVAL_SECS`]'s `MessagePublished` scan — a rotation is rare, and
/// `FactoryResolver::resolve` costs a precompile call plus at least one `eth_getLogs` round trip.
pub const DEFAULT_RESOLVE_POLL_INTERVAL_SECS: u64 = 60;

/// Retry cadence for the startup resolution bootstrap while [`OutboxResolver::resolve`] has not
/// yet produced an address (e.g. `FactoryResolver` still catching up on a long backlog — see
/// `MAX_SCAN_CHUNKS_PER_CALL`). Short: this only blocks the very first scan, not the running loop.
const RESOLVE_BOOTSTRAP_RETRY: Duration = Duration::from_secs(5);

/// Default poll cadence for `eth_getLogs`. WS subscription would be lower-latency but adds an
/// extra failure mode (silent stream stalls) we don't want in PoC scope.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 6;

/// Maximum block span per `eth_getLogs` scan. Public RPCs cap the queryable range; an over-large
/// resume range (long downtime, deep `start_block` backfill) would error on every tick and wedge
/// the watcher forever on the same oversized query. Bounded chunks advance the checkpoint
/// incrementally — at one chunk per 6s tick the watcher catches up quickly.
const MAX_BLOCKS_PER_SCAN: u64 = 5_000;

/// A finalized message that the relayer has discovered on the Creditcoin Outbox. The vote pool
/// keys on `message_hash`; the rest of the fields are needed to recompute the calldata for
/// `Inbox.deliverMessage`.
#[derive(Clone, Debug)]
pub struct IndexedMessage {
    pub chain_key: u64,
    pub message_id: B256,
    pub emitter: Address,
    pub destination_chain_key: B256,
    pub creditcoin_chain_id: u64,
    pub payload: Vec<u8>,
    pub message_hash: B256,
    /// Transaction + block of the `MessagePublished` emission. Carried so the pool can build a
    /// [`ReobservationRequest`](write_ability::envelope::ReobservationRequest) pointing attestors at
    /// the exact event when a message stalls below quorum.
    pub tx_hash: B256,
    pub block_height: u64,
}

/// Spawn one outbox watcher per route. Returns immediately; the watcher loops until `cancel`
/// fires or an unrecoverable error occurs. `scan_lookback_blocks` rewinds the persisted cursor on
/// startup so messages indexed-but-undelivered when the process died are re-discovered (see
/// [`crate::config::DEFAULT_SCAN_LOOKBACK_BLOCKS`]).
#[allow(clippy::too_many_arguments)]
pub async fn watch_outbox(
    route: ChainRoute,
    creditcoin_eth_rpc_url: String,
    indexed_tx: mpsc::Sender<IndexedMessage>,
    metrics: Metrics,
    resolver: Arc<dyn OutboxResolver>,
    checkpoint: Option<Arc<CheckpointStore>>,
    scan_lookback_blocks: u64,
    health: Arc<crate::health::Health>,
    holdback: Arc<crate::checkpoint::CursorHoldback>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let checkpoint_key = format!("outbox:{chain_key}");
    let health_key = checkpoint_key.clone();
    // Register at startup so a watcher that wedges before its first successful scan still goes stale.
    health.heartbeat(&health_key);
    let provider = ProviderBuilder::new()
        .connect(&creditcoin_eth_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: failed to connect to Creditcoin EVM RPC at {creditcoin_eth_rpc_url}"
            )
        })?;

    // `resolve()` needs a type-erased provider so it can be called through the `dyn OutboxResolver`
    // trait object; cloning the concrete provider is cheap (Arc-backed transport) and leaves
    // `provider` itself free for the rest of this function's direct, generic-typed calls.
    let dyn_provider = provider.clone().erased();

    // Startup bootstrap: retry until `resolve()` produces an address. `ConfigOverrideResolver`
    // resolves on the first try or not at all (nothing to wait for); `FactoryResolver` may need
    // several tries on a cold start against a long block-range backlog (see
    // `MAX_SCAN_CHUNKS_PER_CALL`) — each retry resumes its cursor rather than rescanning.
    let resolved = loop {
        match resolver.resolve(&route, &dyn_provider).await {
            Ok(resolved) => break resolved,
            Err(err) => {
                warn!(chain_key, %err, "outbox resolution not ready yet; retrying");
                tokio::select! {
                    () = tokio::time::sleep(RESOLVE_BOOTSTRAP_RETRY) => {}
                    () = cancel.cancelled() => {
                        info!(chain_key, "🛑 Outbox watcher exiting on cancel during resolution");
                        return Ok(());
                    }
                }
            }
        }
    };
    let mut outbox = resolved.address;

    // The destination chain_key is known locally — derived from the route's `u64` chain_key — and
    // bound into messageHash for every event seen on this outbox (see PoC §5.1). It is not read
    // back from the Outbox.
    let destination_chain_key = chain_key_to_bytes32(chain_key);

    let creditcoin_chain_id = provider.get_chain_id().await.with_context(|| {
        format!("chain_key {chain_key}: failed to read Creditcoin EVM chain id")
    })?;

    info!(
        chain_key,
        %outbox,
        ?destination_chain_key,
        creditcoin_chain_id,
        "📡 Outbox watcher initialized"
    );

    // Resume from the persisted cursor (so events emitted while we were down are not skipped),
    // falling back to the current head on first run / when persistence is disabled.
    // The cursor is rewound by `scan_lookback_blocks`: pool votes are memory-only, so a message
    // indexed-but-undelivered before a crash would otherwise be skipped forever (the cursor is
    // past it and stray votes are dropped by the chain-first allowlist). Re-indexing the recent
    // window is idempotent — already-delivered messages re-collect votes via reobservation and
    // resolve as "Already validated" at simulate.
    // A checkpoint is only a valid resume point for the Outbox it was actually scanned against —
    // recorded alongside the block by `set_with_outbox` (see `checkpoint` module docs). Block
    // numbers alone can't substitute for this: a long-lived, never-rotated Outbox's checkpoint is
    // *always* numerically ahead of its own `current_since_block` (you can't publish on a
    // contract before it exists), and so is a stale checkpoint left over from a since-rotated-away
    // Outbox — the two cases are indistinguishable by block number alone, only by address.
    let checkpoint_block = checkpoint.as_ref().and_then(|c| c.get(&checkpoint_key));
    let checkpoint_outbox = checkpoint
        .as_ref()
        .and_then(|c| c.get_outbox(&checkpoint_key));
    let checkpoint_matches_resolved_outbox =
        checkpoint_outbox.as_deref() == Some(resolved.address.to_string().as_str());

    let mut last_seen = if let (Some(block), true) =
        (checkpoint_block, checkpoint_matches_resolved_outbox)
    {
        let resume = block.saturating_sub(scan_lookback_blocks);
        info!(
            chain_key,
            checkpoint = block,
            resume_from = resume + 1,
            "↩️ resuming Outbox scan from checkpoint (rewound by lookback)"
        );
        resume
    } else {
        if let Some(block) = checkpoint_block {
            info!(
                chain_key,
                checkpoint = block,
                recorded_outbox = ?checkpoint_outbox,
                resolved_outbox = %resolved.address,
                "↩️ checkpoint is for a different (or pre-migration, untracked) Outbox address; \
                 not reusing it as a resume point"
            );
        }
        if let Some(since) = resolved.current_since_block {
            info!(
                chain_key,
                since_block = since,
                "⏮️ starting scan from the resolved Outbox's discovery block"
            );
            since.saturating_sub(1)
        } else if let Some(start) = route.start_block {
            info!(
                chain_key,
                start_block = start,
                "⏮️ no Outbox checkpoint; starting initial scan from configured block"
            );
            start.saturating_sub(1)
        } else {
            provider
                .get_block_number()
                .await
                .with_context(|| format!("chain_key {chain_key}: failed to read chain head"))?
        }
    };

    let mut tick = tokio::time::interval(Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut resolve_tick =
        tokio::time::interval(Duration::from_secs(crate::config::poll_secs_override(
            "RELAYER_OUTBOX_RESOLVE_POLL_SECS",
            DEFAULT_RESOLVE_POLL_INTERVAL_SECS,
        )));
    resolve_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 Outbox watcher exiting on cancel");
                return Ok(());
            }
            _ = resolve_tick.tick() => {
                match resolver.resolve(&route, &dyn_provider).await {
                    Ok(fresh) => {
                        if fresh.address != outbox {
                            // In-flight/already-indexed messages are unaffected — the pool tracks
                            // them independently of which Outbox they came from. Only the
                            // MessagePublished scan below switches: new discovery moves to the new
                            // address, resuming at its earliest known block so nothing published
                            // between deployment and this check is missed.
                            info!(
                                chain_key,
                                old = %outbox,
                                new = %fresh.address,
                                "🔁 Outbox rotation detected; switching discovery to the new address"
                            );
                            outbox = fresh.address;
                            last_seen = fresh
                                .current_since_block
                                .map(|b| b.saturating_sub(1))
                                .unwrap_or(last_seen);
                        }
                    }
                    Err(err) => warn!(chain_key, %err, "outbox re-resolution failed; keeping current address"),
                }
            }
            _ = tick.tick() => {
                match poll_once(
                    chain_key,
                    outbox,
                    destination_chain_key,
                    creditcoin_chain_id,
                    route.block_confirmation_depth,
                    &provider,
                    &mut last_seen,
                    &indexed_tx,
                    metrics.as_ref(),
                    &cancel,
                ).await {
                    Ok(()) => {
                        // Successful scan = forward progress; a dead provider errors here instead,
                        // so the heartbeat goes stale and /health trips a restart (C2r).
                        health.heartbeat(&health_key);
                        if let Some(cp) = &checkpoint {
                            // Clamp the *persisted* cursor to before the pool's oldest undelivered
                            // message (fed on its prune tick), so a restart re-indexes every
                            // unfinished message no matter how long it has been stalled. The
                            // in-memory cursor keeps advancing; re-indexing is idempotent
                            // (duplicate slots kept, delivery resolves AlreadyValidated).
                            // Recording which Outbox this cursor was scanned against (not just a
                            // plain `set`) is what lets a future restart's resume logic above tell
                            // a valid long-running checkpoint apart from a stale one left over
                            // from a since-rotated-away Outbox.
                            let persist = holdback.clamp(chain_key, last_seen);
                            if let Err(err) =
                                cp.set_with_outbox(&checkpoint_key, persist, &outbox.to_string())
                            {
                                warn!(chain_key, %err, "failed to persist Outbox checkpoint");
                            }
                        }
                    }
                    Err(err) => warn!(chain_key, %err, "outbox poll iteration failed; will retry"),
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn poll_once<P: Provider>(
    chain_key: u64,
    outbox: Address,
    destination_chain_key: B256,
    creditcoin_chain_id: u64,
    confirmation_depth: u64,
    provider: &P,
    last_seen: &mut u64,
    indexed_tx: &mpsc::Sender<IndexedMessage>,
    metrics: &dyn crate::prom::MetricsTrait,
    cancel: &CancellationToken,
) -> Result<()> {
    let tip = provider.get_block_number().await?;
    let confirmed = tip.saturating_sub(confirmation_depth);
    if confirmed <= *last_seen {
        return Ok(());
    }
    let from_block = *last_seen + 1;
    // Bounded chunk (see MAX_BLOCKS_PER_SCAN): never ask the RPC for more than it will serve.
    let to_block = confirmed.min(last_seen.saturating_add(MAX_BLOCKS_PER_SCAN));

    let filter = Filter::new()
        .address(outbox)
        .event_signature(IOutbox::MessagePublished::SIGNATURE_HASH)
        .from_block(from_block)
        .to_block(to_block);

    let logs = provider
        .get_logs(&filter)
        .await
        .with_context(|| format!("eth_getLogs from {from_block} to {to_block} failed"))?;

    for log in logs {
        match IOutbox::MessagePublished::decode_log(&log.inner) {
            Ok(decoded) => {
                let Some(tx_hash) = log.transaction_hash else {
                    warn!(
                        chain_key,
                        "MessagePublished log without transaction_hash; skipping"
                    );
                    continue;
                };
                let Some(block_height) = log.block_number else {
                    warn!(
                        chain_key,
                        "MessagePublished log without block_number; skipping"
                    );
                    continue;
                };
                let payload = decoded.data.payload.to_vec();
                // `emitterAddress` is emitted as `bytes32` (cross-chain consistency); the 20-byte
                // EVM address sits in the high bytes. Recover the plain `Address` — the signed
                // `messageHash` and `deliverMessage` both use `address`.
                let emitter = alloy::primitives::Address::from_slice(
                    &decoded.data.emitterAddress.as_slice()[..20],
                );
                let hash = message_hash(
                    decoded.data.messageId,
                    emitter,
                    destination_chain_key,
                    creditcoin_chain_id,
                    &payload,
                );
                let indexed = IndexedMessage {
                    chain_key,
                    message_id: decoded.data.messageId,
                    emitter,
                    destination_chain_key,
                    creditcoin_chain_id,
                    payload,
                    message_hash: hash,
                    tx_hash,
                    block_height,
                };
                debug!(
                    chain_key,
                    message_id = %indexed.message_id,
                    message_hash = %indexed.message_hash,
                    "📨 Indexed MessagePublished"
                );
                metrics.inc_messages_indexed(chain_key);
                // Bounded channel. Indexed messages are NOT re-gossiped (they come from chain
                // logs and the cursor advances past them), so they must not be dropped: block if
                // the pool is briefly saturated, but bail promptly on shutdown.
                tokio::select! {
                    res = indexed_tx.send(indexed) => {
                        if res.is_err() {
                            error!(chain_key, "vote pool channel closed — exiting watcher");
                            anyhow::bail!("vote pool channel closed");
                        }
                    }
                    () = cancel.cancelled() => {
                        debug!(chain_key, "cancel during indexed dispatch; stopping poll");
                        return Ok(());
                    }
                }
            }
            Err(err) => {
                warn!(chain_key, %err, "could not decode MessagePublished log; skipping");
            }
        }
    }

    *last_seen = to_block;
    Ok(())
}
