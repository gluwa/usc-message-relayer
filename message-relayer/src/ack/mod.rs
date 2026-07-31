//! Off-chain acknowledgment submitter (research §05/§10).
//!
//! Trust-minimized acknowledgment is **proof-based, not vote-based**. For each route that opts in
//! (`route.ack = Some(..)`), this worker:
//!
//!  1. Watches the **destination** Inbox for `MessageDelivered(bytes32 indexed messageId)` —
//!     evidence that a message was delivered to the destination dApp.
//!  2. For the transaction that emitted it, fetches a native USC delivery proof from the proof-gen
//!     API (`GET {proof_gen_url}/api/v1/proof-by-tx/{chain_key}/{tx_hash}`): the prover `txBytes`
//!     plus the merkle-inclusion and continuity proofs.
//!  3. Submits that proof to the source-chain `AcknowledgmentValidator.submitAcknowledgment(..)`.
//!     The contract verifies the proof against the block-prover precompile, decodes the
//!     `MessageDelivered` logs, and calls `Outbox.acknowledgeMessage` for each — so the relayer
//!     never needs acknowledge authority; the proof is self-validating.
//!
//! ## Relay-fee claiming (`AckAndClaim` mode)
//!
//! When the route has a `RelayerContract` configured (`route.relayer_contract_address = Some(..)`),
//! this same watcher ALSO settles the relay fee: from the same delivery proof it calls
//! `RelayerContract.claimDelivery(messageId, ..)` per delivered message, which pays the relay fee
//! (+ any unexpired tip) to the relayer proven in the destination `MessageDelivered` event.
//!
//! Since usc-contracts #23 the claim does NOT acknowledge — ack settlement lives solely on the
//! `AcknowledgmentValidator` — so the two submissions are independent and BOTH run here, ack first:
//! the message's user-set ackFee is an open bounty paid to the first successful `submitAcknowledgment`
//! sender (front-runnable by design, Jul 28 decision), while `claimDelivery` pays the proven relayer
//! no matter who or when submits. Losing the ack race is therefore terminal-but-harmless for the
//! bounty and never blocks the fee claim. Everything else — the destination watcher, proof-gen
//! fetch, checkpointing, dedup, and backoff — is shared verbatim between the two settlements.
//!
//! Submission is keyed (and deduped) by destination **transaction hash**: one transaction may
//! contain several `MessageDelivered` logs and the validator acknowledges all of them in a single
//! call. A transaction whose block is not yet attested returns HTTP 422 (`BlockNotReady`) from the
//! proof-gen API and is retried on the next tick.

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::network::{Ethereum, EthereumWallet};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolError, SolEvent};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::abi::{IInbox, IOutbox};
use crate::checkpoint::CheckpointStore;
use crate::config::{AckConfig, ChainRoute};
use crate::pending::{BoundedSeen, PendingTxs};
use crate::proofgen::{ProofFetch, ProofGenClient};

/// Poll cadence for the destination `MessageDelivered` watcher and the pending-proof retry queue.
pub const ACK_POLL_INTERVAL_SECS: u64 = 6;

/// Maximum `encodedTransaction` size accepted on-chain by
/// `AcknowledgmentValidator.submitAcknowledgment`. Mirrors `MAX_ENCODED_TRANSACTION_BYTES` in
/// `usc-messaging/contracts/src/AcknowledgmentValidator.sol`; keep the two in sync. Proofs larger
/// than this are rejected on submission (`EncodedTransactionTooLarge`), so we skip them locally
/// instead of paying gas on a guaranteed revert.
pub const MAX_ENCODED_TRANSACTION_BYTES: usize = 500_000;

/// Hard cap on the unacknowledged-tx queue. Without it a prolonged proof-gen outage (or a delivery
/// whose block never attests) would grow `pending` without bound. On overflow the oldest entry is
/// given up (logged) so newer deliveries keep flowing.
const MAX_PENDING_ACKS: usize = 10_000;

/// Hard cap on the set of recently-finished tx hashes kept for in-session dedup. The destination
/// cursor is monotonic, so evicting the oldest entries cannot cause a re-scan to re-process them —
/// this just stops a long-running relayer from leaking one entry per delivery forever.
const MAX_DONE_TRACKED: usize = 10_000;

/// Most pending txs attempted per tick. Bounds how long one tick can run (and how many proof-gen
/// requests it can fan out) regardless of how large `pending` has grown; the rest are retried on
/// subsequent ticks in oldest-first order.
const MAX_ACKS_PER_TICK: usize = 256;

/// Maximum concurrent proof-fetch + submit attempts within a tick. Bounds load on the proof-gen
/// API and the source RPC while still pipelining instead of going strictly serial.
const MAX_ACK_CONCURRENCY: usize = 8;

/// Maximum block span per `eth_getLogs` scan. Public RPCs cap the queryable range; an over-large
/// resume range (long downtime, deep `start_block` backfill) would error on every tick and wedge
/// discovery forever. Bounded chunks advance the cursor incrementally — the 6s tick catches up.
const MAX_BLOCKS_PER_SCAN: u64 = 5_000;

/// Upper bound on waiting for the submitAcknowledgment receipt, so one stuck tx cannot wedge the
/// per-tick pipeline. On timeout the tx stays pending and is retried on a later tick (idempotent:
/// a duplicate lands as `MessageAlreadyAcknowledged`, a terminal revert).
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Upper bound on a single `submitAcknowledgment` broadcast — the gas/fee/nonce reads plus
/// `eth_sendRawTransaction`. Alloy's HTTP transport sets no timeout of its own, so a black-holed
/// Creditcoin RPC would otherwise park this attempt forever, and with it the tick's whole
/// `buffer_unordered` batch and the worker's cancel branch. Bounding it also bounds how long one
/// attempt can hold the signer's broadcast slot.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Retry cadence while the proof block is simply not attested yet (`BlockNotReady`). This is the
/// normal early state of every ack — destination finality plus attestation takes minutes — so it
/// does not count against the transient-failure budget.
const NOT_READY_RETRY: Duration = Duration::from_secs(15);

/// Give up on a tx whose proof never becomes ready (e.g. its block is never attested). Generous:
/// far beyond any healthy finality + attestation latency.
const MAX_ACK_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Give up loudly after this many *transient* submit failures (RPC down, timeout, nonce) — a
/// permanently failing submit (e.g. unfunded ack signer) must not hammer the RPC forever. The
/// per-attempt exponential backoff lives in [`crate::pending`].
const MAX_ACK_TRANSIENT_ATTEMPTS: u32 = 20;

/// Spawn the acknowledgment submitter for one route. Returns immediately when the route has no
/// `ack` config; otherwise loops until `cancel` fires or an unrecoverable error occurs.
/// `scan_lookback_blocks` rewinds the persisted cursor on startup so acks that were pending when
/// the process died are re-discovered (see [`crate::config::DEFAULT_SCAN_LOOKBACK_BLOCKS`]).
pub async fn run(
    route: ChainRoute,
    creditcoin_eth_rpc_url: String,
    checkpoint: Option<Arc<CheckpointStore>>,
    scan_lookback_blocks: u64,
    health: Arc<crate::health::Health>,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let checkpoint_key = format!("ack:{chain_key}");
    let health_key = checkpoint_key.clone();
    let Some(ack) = route.ack.clone() else {
        debug!(chain_key, "ack disabled for route; submitter not started");
        return Ok(());
    };

    // A route with a RelayerContract configured settles the relay fee via `claimDelivery` IN
    // ADDITION to the standalone `submitAcknowledgment` — since usc-contracts #23 the claim no
    // longer bundles the ack, so the two submissions are independent and both must run; see the
    // module docs. The chain key is passed to `claimDelivery` as `bytes32(uint256(chainKey))`,
    // matching the ledger's route check.
    let mode = match route.relayer_contract_address {
        Some(relayer_contract) => SettlementMode::AckAndClaim {
            relayer_contract,
            chain_key: B256::from(U256::from(chain_key)),
        },
        None => SettlementMode::Ack,
    };

    // Register with the health watchdog BEFORE any fallible or blocking setup: `Health::status`
    // only inspects components that have registered, so a worker that never called `heartbeat` is
    // invisible to it and counts as healthy. Both connects below, and the `get_block_number` start
    // lookup on first boot, are unbounded RPC awaits — registering after them means a black-holed
    // endpoint leaves acks permanently unsubmitted while `/health` keeps answering 200. Must stay
    // *after* the `route.ack` guard above, though: a route with acks disabled has no worker to
    // report on, and registering one would make it go stale forever.
    health.heartbeat(&health_key);

    // Read-only provider on the destination chain (where MessageDelivered is emitted).
    let dest_provider = ProviderBuilder::new()
        .connect(&route.destination_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: ack submitter failed to connect to destination RPC at {}",
                route.destination_rpc_url
            )
        })?;

    // Wallet-bearing provider on the source (Creditcoin) chain, where we submit the ack.
    let signer: PrivateKeySigner = ack
        .signer_key
        .trim()
        .parse()
        .with_context(|| format!("chain_key {chain_key}: invalid ack.signer_key"))?;
    let submitter_address = signer.address();
    // Chain-read nonces: a failed broadcast must not consume a nonce the chain never saw, which with
    // a local counter wedges every later ack until restart. The submit loop below fans out
    // `MAX_ACK_CONCURRENCY` sends over this one provider, so they would otherwise all read the same
    // pending count and all but one fail as `nonce too low`; `broadcast_locks` serializes them on the
    // submitter address instead — and, unlike the per-provider counter it replaces, also against any
    // other route configured with this same Creditcoin key. See `crate::broadcast`.
    let source_provider = crate::broadcast::chain_nonce_builder()
        .wallet(EthereumWallet::from(signer))
        .connect(&creditcoin_eth_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: ack submitter failed to connect to Creditcoin EVM RPC at \
                 {creditcoin_eth_rpc_url}"
            )
        })?;

    let client = ProofGenClient::new(&ack.proof_gen_url)?;

    match &mode {
        SettlementMode::Ack => info!(
            chain_key,
            inbox = %route.inbox_address,
            validator = %ack.validator_address,
            submitter = %submitter_address,
            proof_gen_url = %ack.proof_gen_url,
            "🧾 acknowledgment submitter online (ack mode)"
        ),
        SettlementMode::AckAndClaim {
            relayer_contract, ..
        } => info!(
            chain_key,
            inbox = %route.inbox_address,
            validator = %ack.validator_address,
            relayer_contract = %relayer_contract,
            submitter = %submitter_address,
            proof_gen_url = %ack.proof_gen_url,
            "💰 settlement submitter online (ack + relay-fee claim; independent since usc-contracts #23)"
        ),
    }

    // Resume from the persisted cursor so MessageDelivered events emitted while we were down are
    // not skipped; fall back to the current head on first run / when persistence is disabled.
    // The cursor is rewound by `scan_lookback_blocks`: the pending-ack queue is memory-only, so a
    // delivery discovered-but-not-acknowledged before a crash would otherwise be skipped forever.
    // Re-processing is cheap — already-acked / no-ack-needed txs are skipped by the requiresAck
    // pre-check before any proof is fetched.
    let mut last_seen = match checkpoint.as_ref().and_then(|c| c.get(&checkpoint_key)) {
        Some(block) => {
            let resume = block.saturating_sub(scan_lookback_blocks);
            info!(
                chain_key,
                checkpoint = block,
                resume_from = resume + 1,
                "↩️ resuming ack scan from checkpoint (rewound by lookback)"
            );
            resume
        }
        None => {
            if let Some(start) = ack.start_block {
                info!(
                    chain_key,
                    start_block = start,
                    "⏮️ no ack checkpoint; starting initial scan from configured block"
                );
                start.saturating_sub(1)
            } else {
                dest_provider.get_block_number().await.with_context(|| {
                    format!("chain_key {chain_key}: ack submitter failed to read chain head")
                })?
            }
        }
    };

    // Destination tx hashes seen but not yet acknowledged (proof not ready / transient failure).
    let mut pending = PendingTxs::new(MAX_PENDING_ACKS);
    // Tx hashes already acknowledged (or terminally skipped) — never re-submitted (bounded).
    let mut done = BoundedSeen::new(MAX_DONE_TRACKED);

    let mut tick = tokio::time::interval(Duration::from_secs(ACK_POLL_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 acknowledgment submitter exiting on cancel");
                return Ok(());
            }
            _ = tick.tick() => {
                match discover_delivered(
                    chain_key,
                    route.inbox_address,
                    ack.confirmation_depth,
                    &dest_provider,
                    &mut last_seen,
                    &mut pending,
                    &done,
                ).await {
                    Ok(()) => {
                        // Successful destination scan = loop progress (C2r).
                        health.heartbeat(&health_key);
                        if let Some(cp) = &checkpoint {
                            // Clamp the *persisted* cursor so it never advances past a tx that is
                            // still pending (proof not ready / retrying): a restart then rescans
                            // from before the oldest unfinished tx and re-discovers it, no matter
                            // how long it was pending. The in-memory cursor keeps advancing, so the
                            // live scan never re-reads; re-discovery on restart is idempotent
                            // (requiresAck / AlreadyAcknowledged pre-checks).
                            let persist = pending
                                .oldest_pending_block()
                                .map_or(last_seen, |b| last_seen.min(b.saturating_sub(1)));
                            if let Err(err) = cp.set(&checkpoint_key, persist) {
                                warn!(chain_key, %err, "failed to persist ack checkpoint");
                            }
                        }
                    }
                    Err(err) => warn!(chain_key, %err, "ack discovery iteration failed; will retry"),
                }

                process_pending(
                    chain_key,
                    &ack,
                    &mode,
                    route.outbox_address,
                    &client,
                    &source_provider,
                    submitter_address,
                    &broadcast_locks,
                    &mut pending,
                    &mut done,
                ).await;
            }
        }
    }
}

/// Poll the destination Inbox for new `MessageDelivered` events and enqueue their tx hashes.
///
/// Scans only up to `tip - confirmation_depth` so a destination reorg on the unsafe head cannot
/// enqueue an ack for a delivery that later disappears.
async fn discover_delivered<P: Provider>(
    chain_key: u64,
    inbox: alloy::primitives::Address,
    confirmation_depth: u64,
    provider: &P,
    last_seen: &mut u64,
    pending: &mut PendingTxs,
    done: &BoundedSeen,
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
        .address(inbox)
        .event_signature(IInbox::MessageDelivered::SIGNATURE_HASH)
        .from_block(from_block)
        .to_block(to_block);

    let logs = provider.get_logs(&filter).await.with_context(|| {
        format!("eth_getLogs MessageDelivered from {from_block} to {to_block} failed")
    })?;

    for log in logs {
        let Some(tx_hash) = log.transaction_hash else {
            warn!(
                chain_key,
                "MessageDelivered log without transaction_hash; skipping"
            );
            continue;
        };
        let Some(block) = log.block_number else {
            warn!(
                chain_key,
                %tx_hash,
                "MessageDelivered log without block_number; skipping"
            );
            continue;
        };
        // The delivered messageId feeds the requiresAck pre-check on the source Outbox, so bridge
        // traffic never costs a proof fetch. A tx may carry several MessageDelivered logs.
        let message_id = match IInbox::MessageDelivered::decode_log(&log.inner) {
            Ok(decoded) => decoded.data.messageId,
            Err(err) => {
                warn!(chain_key, %tx_hash, %err, "could not decode MessageDelivered log; skipping");
                continue;
            }
        };
        if done.contains(&tx_hash) {
            continue;
        }
        if pending.contains(&tx_hash) {
            pending.note_meta(&tx_hash, message_id);
            continue;
        }
        if let Some(evicted) = pending.insert(tx_hash, Instant::now(), block, vec![message_id]) {
            warn!(
                chain_key,
                %evicted,
                "ack pending queue at capacity; giving up on oldest un-acknowledged delivery"
            );
        }
        debug!(chain_key, %tx_hash, %message_id, "🧾 observed MessageDelivered; queued for acknowledgment");
    }

    *last_seen = to_block;
    Ok(())
}

/// Try to fetch a proof and submit an acknowledgment for every pending destination tx that is due
/// for an attempt. Successful (or terminally-reverting) submissions move to `done`; not-yet-ready
/// proofs are deferred by [`NOT_READY_RETRY`]; transient failures back off exponentially and give
/// up after [`MAX_ACK_TRANSIENT_ATTEMPTS`].
#[allow(clippy::too_many_arguments)]
async fn process_pending<P: Provider>(
    chain_key: u64,
    ack: &AckConfig,
    mode: &SettlementMode,
    outbox: Option<alloy::primitives::Address>,
    client: &ProofGenClient,
    source_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    pending: &mut PendingTxs,
    done: &mut BoundedSeen,
) {
    // Retry oldest-first, a bounded batch per tick, so a large backlog cannot make one tick run
    // unboundedly long (or starve `discover_delivered` / shutdown).
    let now = Instant::now();
    let batch = pending.ready(MAX_ACKS_PER_TICK, now);
    if batch.is_empty() {
        return;
    }

    // Fetch proofs + submit with bounded concurrency rather than strictly serially: each attempt
    // is independent and dominated by network latency. Mutations to `pending`/`done` are applied
    // afterwards, on this task, so no shared-state synchronization is needed.
    let results: Vec<(B256, Result<AckOutcome>)> = futures::stream::iter(batch)
        .map(|(tx_hash, message_ids)| async move {
            let outcome = acknowledge_tx(
                chain_key,
                ack,
                mode,
                outbox,
                &message_ids,
                client,
                source_provider,
                submitter_address,
                broadcast_locks,
                tx_hash,
            )
            .await;
            (tx_hash, outcome)
        })
        .buffer_unordered(MAX_ACK_CONCURRENCY)
        .collect()
        .await;

    let now = Instant::now();
    for (tx_hash, outcome) in results {
        match outcome {
            Ok(AckOutcome::Acknowledged) => {
                info!(chain_key, %tx_hash, "✅ delivery settled on source chain");
                pending.remove(&tx_hash);
                done.insert(tx_hash);
            }
            Ok(AckOutcome::Terminal(reason)) => {
                info!(chain_key, %tx_hash, %reason, "ack skipped (terminal); will not retry");
                pending.remove(&tx_hash);
                done.insert(tx_hash);
            }
            Ok(AckOutcome::NotReady) => {
                // Normal early state (destination finality + attestation take minutes) — defer
                // without burning the transient budget, but don't wait forever on a block that
                // never attests.
                if pending.age(&tx_hash, now) > Some(MAX_ACK_AGE) {
                    warn!(
                        chain_key,
                        %tx_hash,
                        "proof never became ready within {MAX_ACK_AGE:?}; giving up on this ack"
                    );
                    pending.remove(&tx_hash);
                    done.insert(tx_hash);
                } else {
                    debug!(chain_key, %tx_hash, "proof not ready yet; deferred");
                    pending.defer(&tx_hash, now + NOT_READY_RETRY);
                }
            }
            Err(err) => {
                let attempts = pending.record_transient_failure(&tx_hash, now);
                // Do NOT drop after a fixed budget. The old give-up removed the tx and marked it
                // `done`, so a multi-hour proof-gen / Creditcoin-RPC outage (proof-gen infra errors
                // are `Err`, not `NotReady`) silently and *permanently* lost every ack discovered
                // before it — unrecoverable even across restarts, because the discovery cursor
                // already advanced past the tx and the ~2.7h exhaustion time exceeds the scan
                // lookback window (C1r/C2). Keep retrying at the capped backoff instead
                // (TRANSIENT_BACKOFF_MAX = 10min): re-submission is idempotent on-chain
                // (AlreadyAcknowledged), and the queue stays memory-bounded by its cap. Escalate the
                // log past the old budget so a genuinely stuck ack is alertable.
                if attempts >= MAX_ACK_TRANSIENT_ATTEMPTS {
                    warn!(
                        chain_key,
                        %tx_hash,
                        attempts,
                        %err,
                        "ack still failing after {MAX_ACK_TRANSIENT_ATTEMPTS}+ transient attempts; \
                         continuing to retry at capped backoff (operator action likely required — \
                         check the ack signer balance, proof-gen, and the Creditcoin RPC)"
                    );
                } else {
                    warn!(
                        chain_key,
                        %tx_hash,
                        attempts,
                        %err,
                        "ack attempt failed transiently; will retry with backoff"
                    );
                }
            }
        }
    }
}

/// What this worker submits once a delivery proof is ready — chosen per route in [`run`].
#[derive(Clone, Copy, Debug)]
enum SettlementMode {
    /// No RelayerContract on the route: prove delivery to the `AcknowledgmentValidator` only
    /// (`submitAcknowledgment`, one call per tx — the validator acks every `MessageDelivered` log
    /// under try/catch). The validator address comes from `ack.validator_address`.
    Ack,
    /// The route has a `RelayerContract` (fee ledger): submit BOTH settlements from one proof —
    /// `submitAcknowledgment` (which also earns the message's user-set ackFee, an open bounty paid
    /// to the first submitter) and `claimDelivery` per messageId (relay fee + tip, always paid to
    /// the proven relayer). Since usc-contracts #23 the claim does NOT acknowledge, so skipping
    /// either call would leave messages unacknowledged or fees unclaimed. `chain_key` is passed to
    /// `claimDelivery` as `bytes32(uint256(chainKey))`.
    AckAndClaim {
        relayer_contract: Address,
        chain_key: B256,
    },
}

enum AckOutcome {
    /// Proof verified and the settlement call (`submitAcknowledgment` / `claimDelivery`) succeeded
    /// or was already terminal for every message — either way the tx is resolved.
    Acknowledged,
    /// The proof block is not yet attested (`BlockNotReady`); retry later.
    NotReady,
    /// A permanent condition (e.g. on-chain revert: already acknowledged / does not require ack).
    Terminal(String),
}

/// Result of one confirmed-or-terminal on-chain submission; transient failures are `Err` (retryable).
enum SubmitOutcome {
    /// Mined successfully. Fields are the on-chain gas cost, recorded via Display (`%`) because
    /// `tracing` has no native u128 value impl.
    Confirmed {
        gas_used: u128,
        effective_gas_price: u128,
        gas_cost_wei: u128,
        tx_hash: B256,
    },
    /// A permanent on-chain condition (revert: already settled / does not require ack / reverted).
    Terminal(String),
}

/// Await a broadcast result and classify it, shared by both submit paths so the receipt-wait, revert
/// classification, and gas accounting cannot drift between ack and claim. `Err` is a transient
/// failure the caller should retry; `Ok(Terminal)` is permanent. `call` names the call for logs.
async fn classify_submit(
    pending_tx: Result<PendingTransactionBuilder<Ethereum>, alloy::contract::Error>,
    call: &str,
) -> Result<SubmitOutcome> {
    match pending_tx {
        // `crate::receipt::await_receipt` instead of `builder.get_receipt()`: the latter runs on
        // alloy's block-decoding heartbeat, which wedges against Frontier's mixHash-less blocks
        // (see the `receipt` module docs).
        Ok(builder) => {
            match tokio::time::timeout(RECEIPT_TIMEOUT, crate::receipt::await_receipt(&builder))
                .await
            {
                Err(_elapsed) => Err(anyhow!(
                    "no receipt within {RECEIPT_TIMEOUT:?} ({call} tx possibly stuck)"
                )),
                Ok(Ok(receipt)) if receipt.status() => {
                    let gas_used = u128::from(receipt.gas_used);
                    let effective_gas_price = receipt.effective_gas_price;
                    Ok(SubmitOutcome::Confirmed {
                        gas_used,
                        effective_gas_price,
                        gas_cost_wei: gas_used.saturating_mul(effective_gas_price),
                        tx_hash: receipt.transaction_hash,
                    })
                }
                Ok(Ok(_)) => Ok(SubmitOutcome::Terminal("tx mined but reverted".into())),
                Ok(Err(err)) => Err(anyhow!("receipt fetch failed: {err}")),
            }
        }
        Err(err) if is_terminal_revert(&err) => Ok(SubmitOutcome::Terminal(describe_revert(&err))),
        Err(err) => Err(anyhow!("{call} send failed: {err}")),
    }
}

/// MessageIds in `ids` whose relay fee is still claimable: funded through the RelayerContract
/// ledger (`payer != 0`) and not yet settled. Empty means nothing to claim for this tx. Traffic
/// funded outside the relayer (e.g. bridge messages) reports `payer == 0` and is skipped.
async fn relay_claimable_ids<P: Provider>(
    provider: &P,
    relayer_contract: Address,
    ids: &[B256],
) -> Result<Vec<B256>> {
    let ledger = crate::abi::IRelayerContract::new(relayer_contract, provider);
    let mut claimable = Vec::new();
    for id in ids {
        let info = ledger
            .getMessageInfo(*id)
            .call()
            .await
            .context("IRelayerContract.getMessageInfo call failed")?;
        if info.payer != Address::ZERO && !info.relaySettled {
            claimable.push(*id);
        }
    }
    Ok(claimable)
}

/// Fetch the delivery proof for `tx_hash` and submit it to the source `AcknowledgmentValidator`.
///
/// Before any proof is fetched, the delivered messageIds are checked against the source Outbox:
/// when none requires an acknowledgment (bridge traffic publishes `requiresAck = false`) or all
/// are already acknowledged, the tx is terminal without costing a proof-gen round-trip or a
/// guaranteed-revert gas estimate.
#[allow(clippy::too_many_arguments)]
async fn acknowledge_tx<P: Provider>(
    chain_key: u64,
    ack: &AckConfig,
    mode: &SettlementMode,
    outbox: Option<alloy::primitives::Address>,
    message_ids: &[B256],
    client: &ProofGenClient,
    source_provider: &P,
    submitter_address: alloy::primitives::Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    tx_hash: B256,
) -> Result<AckOutcome> {
    // Pre-checks: skip the proof fetch entirely when nothing is left to do. Both checks fail
    // open — a view-call error falls through to the proof path, where the contracts enforce the
    // same rules on-chain; this is purely a cost-saving shortcut. The two settlements are
    // independent (usc-contracts #23: `claimDelivery` no longer acknowledges), so the tx is only
    // terminal when NEITHER an ack nor a claim remains outstanding.
    let needs_ack: bool = if let Some(outbox_addr) = outbox {
        if message_ids.is_empty() {
            true // discovery always records ids; treat the impossible case fail-open
        } else {
            match any_requires_ack(source_provider, outbox_addr, message_ids).await {
                Ok(needed) => needed,
                Err(err) => {
                    warn!(chain_key, %tx_hash, %err, "requiresAck pre-check failed; assuming ack needed");
                    true
                }
            }
        }
    } else {
        true // no Outbox view configured — let the validator decide on-chain
    };

    let claim_ids: Vec<B256> = match mode {
        SettlementMode::Ack => Vec::new(),
        SettlementMode::AckAndClaim {
            relayer_contract, ..
        } => match relay_claimable_ids(source_provider, *relayer_contract, message_ids).await {
            Ok(ids) => ids,
            Err(err) => {
                warn!(chain_key, %tx_hash, %err, "relay-claimable pre-check failed; attempting all ids");
                message_ids.to_vec()
            }
        },
    };

    if !needs_ack && claim_ids.is_empty() {
        return Ok(AckOutcome::Terminal(
            "nothing left to settle (no message requires an ack, no unsettled relay fee)".into(),
        ));
    }

    let proof = match client.proof_by_tx(chain_key, tx_hash).await? {
        ProofFetch::Ready(p) => p,
        ProofFetch::NotReady => return Ok(AckOutcome::NotReady),
    };

    let encoded_tx = proof.encoded_transaction()?;

    // Mirror the on-chain cap: an oversized prover txBytes payload is rejected on-chain
    // (EncodedTransactionTooLarge) — the bytes now travel inside `inclusionProof.data`, but the cap
    // is enforced on the same decoded length — so skip it before spending gas on a guaranteed
    // revert. Permanent for this proof, hence Terminal (no retry).
    if encoded_tx.len() > MAX_ENCODED_TRANSACTION_BYTES {
        return Ok(AckOutcome::Terminal(format!(
            "encodedTransaction {} bytes exceeds on-chain max {} bytes",
            encoded_tx.len(),
            MAX_ENCODED_TRANSACTION_BYTES
        )));
    }

    let height = proof.header_number;

    // Serialized on the submitter address so this tick's concurrent sends (and any other worker
    // sharing this Creditcoin key) cannot read the same chain nonce. The guard (inside `broadcast`)
    // covers the broadcast only — the receipt is awaited in `classify_submit`, outside it, so one
    // confirmation does not stall the batch. A stall consumes no nonce, so it is reported as
    // transient and retried (idempotently: a duplicate lands as `MessageAlreadyAcknowledged` /
    // `RelayAlreadySettled`).
    //
    // Ack FIRST, claim second: the ack fee is an open bounty paid to the first successful
    // submitter (front-runnable by design), while the relay-fee claim always pays the proven
    // relayer no matter who or when submits — so the time-sensitive settlement goes first.
    // A transient failure anywhere aborts the whole tx for retry; both settlements are idempotent
    // on-chain, and the pre-checks drop already-settled work on the retry, so retries converge.
    if needs_ack {
        let (inclusion, continuity) = proof.to_inclusion_and_continuity()?;
        let validator =
            crate::abi::IAcknowledgmentValidator::new(ack.validator_address, source_provider);
        let pending_tx = match broadcast_locks
            .broadcast(
                submitter_address,
                SEND_TIMEOUT,
                validator
                    .submitAcknowledgment(height, inclusion, continuity)
                    .send(),
            )
            .await
        {
            Ok(res) => res,
            Err(stalled) => return Err(anyhow!("submitAcknowledgment {stalled}")),
        };
        match classify_submit(pending_tx, "submitAcknowledgment").await? {
            SubmitOutcome::Confirmed {
                gas_used,
                effective_gas_price,
                gas_cost_wei,
                tx_hash: settle_tx,
            } => {
                info!(
                    chain_key,
                    %tx_hash,
                    ack_tx_hash = %settle_tx,
                    gas_used = %gas_used,
                    effective_gas_price_wei = %effective_gas_price,
                    gas_cost_wei = %gas_cost_wei,
                    "submitAcknowledgment confirmed (ack fee, if any, paid to this submitter)",
                );
            }
            // Terminal here (e.g. NoMessageDeliveredLogs because another submitter front-ran the
            // bounty and every log is now already-acked) must not block the relay-fee claim below —
            // the claim pays the proven relayer regardless of who acknowledged.
            SubmitOutcome::Terminal(reason) => {
                info!(chain_key, %tx_hash, %reason, "submitAcknowledgment terminal; continuing to claim");
            }
        }
    }

    // One claimDelivery per messageId (the ledger settles a single message per call, unlike the
    // validator which acks every log in one tx). A tx usually carries one delivery, so the proof
    // structs are rebuilt per id rather than cloned.
    if let SettlementMode::AckAndClaim {
        relayer_contract,
        chain_key: ck,
    } = mode
    {
        let ledger = crate::abi::IRelayerContract::new(*relayer_contract, source_provider);
        for id in &claim_ids {
            let (inclusion, continuity) = proof.to_inclusion_and_continuity()?;
            let pending_tx = match broadcast_locks
                .broadcast(
                    submitter_address,
                    SEND_TIMEOUT,
                    ledger
                        .claimDelivery(*id, *ck, height, inclusion, continuity)
                        .send(),
                )
                .await
            {
                Ok(res) => res,
                Err(stalled) => return Err(anyhow!("claimDelivery {stalled}")),
            };
            match classify_submit(pending_tx, "claimDelivery").await? {
                SubmitOutcome::Confirmed {
                    gas_used,
                    effective_gas_price,
                    gas_cost_wei,
                    tx_hash: settle_tx,
                } => info!(
                    chain_key,
                    %tx_hash,
                    message_id = %id,
                    claim_tx_hash = %settle_tx,
                    gas_used = %gas_used,
                    effective_gas_price_wei = %effective_gas_price,
                    gas_cost_wei = %gas_cost_wei,
                    "claimDelivery confirmed (relay fee settled to proven relayer)",
                ),
                SubmitOutcome::Terminal(reason) => info!(
                    chain_key,
                    %tx_hash,
                    message_id = %id,
                    %reason,
                    "claimDelivery skipped for message (terminal)",
                ),
            }
        }
    }

    Ok(AckOutcome::Acknowledged)
}

/// Whether any of `ids` still needs an acknowledgment on the source Outbox: published with
/// `requiresAck = true`, known to the outbox (`emitter != 0`), and not yet acknowledged.
async fn any_requires_ack<P: Provider>(
    provider: &P,
    outbox: alloy::primitives::Address,
    ids: &[B256],
) -> Result<bool> {
    let outbox = IOutbox::new(outbox, provider);
    for id in ids {
        if !outbox
            .messageRequiresAck(*id)
            .call()
            .await
            .context("IOutbox.messageRequiresAck call failed")?
        {
            // `messageRequiresAck` is false for an unknown id (mapping default), so passing this
            // gate already implies the message exists — no separate existence check needed.
            continue;
        }
        if !outbox
            .isAcknowledged(*id)
            .call()
            .await
            .context("IOutbox.isAcknowledged call failed")?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Decode a known ack-path revert selector into its error name, for actionable Terminal logs
/// (Creditcoin's EVM RPC returns raw selector data with no decoded name). Selectors come from the
/// shared [`write_ability::abi`] `sol!` declarations, so they cannot drift from the contracts.
fn ack_revert_name(sel: [u8; 4]) -> Option<&'static str> {
    use crate::abi::{IAcknowledgmentValidator as V, IOutbox as O, IRelayerContract as RC};
    Some(match sel {
        s if s == O::MessageDoesNotRequireAck::SELECTOR => "MessageDoesNotRequireAck",
        s if s == O::MessageAlreadyAcknowledged::SELECTOR => "MessageAlreadyAcknowledged",
        s if s == O::MessageNotFound::SELECTOR => "MessageNotFound",
        s if s == V::ProofInvalid::SELECTOR => "ProofInvalid",
        s if s == V::NoMessageDeliveredLogs::SELECTOR => "NoMessageDeliveredLogs",
        s if s == RC::RelayAlreadySettled::SELECTOR => "RelayAlreadySettled",
        s if s == RC::UnknownOperation::SELECTOR => "UnknownOperation",
        _ => return None,
    })
}

/// Classify a submit error as a permanent on-chain revert (vs. a transient RPC failure). A contract
/// revert observed at send / gas-estimation time is deterministic, so it must be terminal — otherwise
/// the tx is retried forever (e.g. every bridge Release delivery, which reverts
/// `MessageDoesNotRequireAck`). Matches revert phrasing across node dialects (see [`crate::revert`])
/// plus decoded error names as a fallback.
fn is_terminal_revert(err: &impl std::fmt::Display) -> bool {
    let s = err.to_string();
    if crate::revert::is_revert(&s) {
        return true;
    }
    // Decoded error-name fallback (nodes that surface the custom-error name without standard
    // revert phrasing).
    s.contains("AlreadyAcknowledged")
        || s.contains("DoesNotRequireAck")
        || s.contains("MessageNotFound")
        || s.contains("ProofInvalid")
        || s.contains("NoMessageDeliveredLogs")
        || s.contains("RelayAlreadySettled")
        || s.contains("UnknownOperation")
}

/// Prefix a terminal revert with the decoded error name when the selector is recognized, so the
/// `ack skipped (terminal)` log tells the operator *why* without a manual selector lookup.
fn describe_revert(err: &impl std::fmt::Display) -> String {
    let s = err.to_string();
    match crate::revert::revert_selector(&s).and_then(ack_revert_name) {
        Some(name) => format!("{name}: {s}"),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_revert_classification() {
        // Decoded-name form (nodes that surface the custom-error name).
        assert!(is_terminal_revert(&"reverted: MessageAlreadyAcknowledged"));
        assert!(is_terminal_revert(&"execution reverted"));

        // Creditcoin EVM RPC form: raw selector data, no decoded name — this is what was slipping
        // through and retrying forever on every bridge Release delivery (MessageDoesNotRequireAck).
        assert!(is_terminal_revert(
            &"submitAcknowledgment send failed: server returned an error response: error code \
              -32603: VM Exception while processing transaction: revert, data: \
              \"0x2f28bb55c8e0b2db4217508f44fb2d148bd9fab3c94e876a56a3fdbcf71f17570ecbe54c\""
        ));
        // Unknown selector but a clear revert phrasing is still terminal.
        assert!(is_terminal_revert(
            &"VM Exception while processing transaction: revert, data: \"0xdeadbeef\""
        ));

        // Genuine transient infra failures stay retryable.
        assert!(!is_terminal_revert(
            &"error sending request: connection refused"
        ));
        assert!(!is_terminal_revert(
            &"server returned an error response: error code -32000: insufficient funds for gas"
        ));
    }

    #[test]
    fn describe_revert_decodes_known_selectors() {
        // The real-world Creditcoin node string for a bridge Release delivery: raw selector, no
        // name. The Terminal log should still name the error for the operator.
        let s = "VM Exception while processing transaction: revert, data: \
                 \"0x2f28bb55c8e0b2db4217508f44fb2d148bd9fab3c94e876a56a3fdbcf71f17570ecbe54c\"";
        assert!(describe_revert(&s).starts_with("MessageDoesNotRequireAck: "));
        // Unknown selector passes through unchanged.
        let unknown = "revert, data: \"0xdeadbeef\"";
        assert_eq!(describe_revert(&unknown), unknown);
        // Selector constants in the shared ABI must still hash to the on-wire values.
        assert_eq!(
            crate::abi::IOutbox::MessageDoesNotRequireAck::SELECTOR,
            [0x2f, 0x28, 0xbb, 0x55]
        );
        assert_eq!(
            crate::abi::IOutbox::MessageAlreadyAcknowledged::SELECTOR,
            [0x33, 0x70, 0x4b, 0x28]
        );
        assert_eq!(
            crate::abi::IOutbox::MessageNotFound::SELECTOR,
            [0x5d, 0x80, 0x3c, 0xca]
        );
    }
}
