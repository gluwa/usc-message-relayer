//! Per-route delivery worker.
//!
//! Consumes [`DeliveryJob`]s from the vote pool and submits `Inbox.deliverMessage(...)` on the
//! destination chain. Implements the PoC §7 + §9 behaviour:
//!
//!  1. (Optional) `eth_call` simulate to catch `validateVotes` reverts before paying gas.
//!     Simulation distinguishes reverts (terminal / already-validated) from transport failures
//!     (returned to the pool's bounded retry) — a mere RPC blip must not drop a message.
//!  2. Send the transaction, watching for receipt (bounded by [`RECEIPT_TIMEOUT`] so a stuck
//!     underpriced tx cannot wedge the route's serial worker).
//!  3. Classify the outcome. Note `MessagePending` is an **event on a successful tx** (the inbox
//!     validated the votes but the dApp's `receiveMessage` reverted) — it is detected from the
//!     receipt logs, not from a revert.
//!  4. On `MessagePending`, schedule bounded `retryPendingMessage` attempts (permissionless).
//!  5. On RPC-level failure, retry up to `delivery.max_retries` with backoff.
//!
//! The worker processes one job at a time per route — serial nonce management is the simplest
//! approach for PoC scope and matches PoC §7.2 ("optional multiple wallets for throughput, out
//! of PoC scope"). Each route runs in its own [`tokio::spawn`] so a slow destination chain
//! does not block the others.

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolError, SolEvent};
use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::abi::{IInbox, IRelayerContract};
use crate::config::{ChainRoute, DeliveryConfig};
use crate::prom::{DeliveryStatus, Metrics};
use crate::revert::{has_selector, is_revert};

pub mod encode;

/// Initial retry backoff. Subsequent attempts double the wait, capped by [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Upper bound on waiting for a delivery receipt. Without it, one stuck (e.g. underpriced) tx
/// blocks the route's serial worker — and every message queued behind it — indefinitely. On
/// timeout the job returns to the pool's bounded retry; if the stuck tx mines later, the next
/// attempt's simulate detects the duplicate ("Already validated") and resolves idempotently.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Cadence of the delivery worker's liveness heartbeat. Must stay comfortably under the health
/// watchdog's staleness deadline so an idle route — one with no messages to deliver — is never
/// mistaken for a wedged one.
const HEALTH_TICK: Duration = Duration::from_secs(15);

/// Upper bound on the per-job funded-gas RPC reads (`RelayerContract.getMessageInfo` on the
/// source, and the under-funding `estimate_gas` on the destination). Both sit in the serial
/// worker's critical path, so a stalled RPC must not park the route — on timeout the job degrades
/// gracefully (estimation fallback / bounded retry) instead of wedging.
const FUNDED_GAS_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Upper bound on a single `send()` — the gas/fee/nonce reads plus `eth_sendRawTransaction`. Alloy's
/// HTTP transport has no timeout of its own, so without this a black-holed RPC parks the route (and
/// starves the cancel branch, so SIGTERM is ignored) forever. Generous enough that a merely slow
/// endpoint still succeeds.
///
/// Abandoning a send here no longer costs a nonce: sends go through
/// [`crate::broadcast::BroadcastLocks`] against a chain-read nonce, so a broadcast that never reached
/// the node leaves the pending count untouched and the next attempt re-reads the same nonce. What a
/// timeout here *does* leave is genuine ambiguity about whether the tx landed — resolved
/// idempotently, since the next attempt's simulate detects an already-validated message.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Sanity ceiling on a funded gasLimit read from the vault. Real per-tx gas is far below this; a
/// value above it means a misconfigured `--relayer-fee-vault-address` (an unrelated contract whose
/// `getMessageInfo` ABI-decodes to junk), so we ignore it and estimate rather than pin an
/// unincludable `.gas()` on every delivery for the route.
const MAX_FUNDED_GAS: u64 = 100_000_000;

/// Bounded, permissionless `retryPendingMessage` schedule after a delivery lands in the
/// `MessagePending` state (dApp callback reverted). Backoff gives the destination dApp time to
/// recover (e.g. gas market spike); anyone else may also retry, so this is best-effort.
const PENDING_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(15),
    Duration::from_secs(60),
    Duration::from_secs(240),
];

/// Job dispatched by the pool when a `messageHash` clears the threshold.
#[derive(Clone, Debug)]
pub struct DeliveryJob {
    pub chain_key: u64,
    pub message_id: B256,
    pub emitter: Address,
    pub message_hash: B256,
    pub payload: Vec<u8>,
    pub votes_calldata: Vec<u8>,
    pub signer_count: usize,
    pub indexed_at: Instant,
}

#[derive(Clone, Debug)]
pub struct DeliveryResult {
    pub chain_key: u64,
    pub message_hash: B256,
    pub outcome: DeliveryResultKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryResultKind {
    Delivered,
    Terminal,
    Retryable,
}

/// Spawn the delivery worker for one route. Exits on `cancel` or unrecoverable channel close.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    route: ChainRoute,
    delivery_config: DeliveryConfig,
    creditcoin_eth_rpc_url: String,
    mut job_rx: mpsc::Receiver<DeliveryJob>,
    result_tx: mpsc::Sender<DeliveryResult>,
    metrics: Metrics,
    health: Arc<crate::health::Health>,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    cancel: CancellationToken,
) -> Result<()> {
    let chain_key = route.chain_key;
    let health_key = format!("delivery:{chain_key}");

    // Register with the health watchdog BEFORE any fallible or blocking setup, because
    // `Health::status` only inspects components that have registered: a worker that never called
    // `heartbeat` is invisible to it and therefore counts as healthy. Registering after the RPC
    // connects would mean a connect that hangs (black-holed endpoint, TCP with no RST) leaves this
    // route permanently dead while `/health` keeps answering 200 and Kubernetes never restarts the
    // pod — the exact failure class the watchdog exists to catch. The outbox watcher orders it the
    // same way; keep them consistent.
    health.heartbeat(&health_key);

    let signer_key = route
        .signer_key
        .clone()
        .with_context(|| format!("chain_key {chain_key}: signer_key is required to deliver"))?;
    let signer: PrivateKeySigner = signer_key
        .trim()
        .parse()
        .with_context(|| format!("chain_key {chain_key}: invalid signer_key"))?;

    let signer_address = signer.address();
    let wallet = EthereumWallet::from(signer);
    // Chain-read nonces, so a broadcast that fails after `prepare` (RPC 502, SEND_TIMEOUT
    // abandonment, LB failover) does not consume a nonce the chain never saw and wedge the route
    // until restart. Every send from this signer — this worker's, the detached
    // `spawn_pending_retry` tasks holding provider clones, and the set-update submitter, which
    // shares `route.signer_key` — serializes through `broadcast_locks` instead of through a
    // per-provider local counter. The two halves are only correct together; see `crate::broadcast`.
    let provider = crate::broadcast::chain_nonce_builder()
        .wallet(wallet)
        .connect(&route.destination_rpc_url)
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: failed to connect to destination RPC at {}",
                route.destination_rpc_url
            )
        })?;

    // Read-only source-chain provider, only when the relayer contract is configured: used to look
    // up each message's funded `gasLimit` so the delivery tx is pinned to it (see `funded_gas_limit`).
    let source_provider = match route.relayer_contract_address {
        Some(_) => Some(
            ProviderBuilder::new()
                .connect(&creditcoin_eth_rpc_url)
                .await
                .with_context(|| {
                    format!(
                        "chain_key {chain_key}: failed to connect to source EVM RPC at {creditcoin_eth_rpc_url} \
                         (needed to read funded gasLimit from the RelayerContract ledger)"
                    )
                })?,
        ),
        None => None,
    };

    info!(
        chain_key,
        signer = %signer_address,
        inbox = %route.inbox_address,
        relayer_contract = ?route.relayer_contract_address,
        "🚚 delivery worker online"
    );

    // Liveness tick. This worker is idle-driven: it blocks on `job_rx.recv()`, so a route with no
    // traffic would otherwise never heartbeat and would be reported stale purely for being quiet.
    // Beating on this interval means "the select loop is still turning", which is the property we
    // actually want to assert; per-job progress is reported separately below.
    let mut liveness = tokio::time::interval(HEALTH_TICK);
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(chain_key, "🛑 delivery worker exiting on cancel");
                return Ok(());
            }
            _ = liveness.tick() => {
                health.heartbeat(&health_key);
            }
            maybe = job_rx.recv() => {
                let Some(job) = maybe else {
                    info!(chain_key, "delivery channel closed; worker exiting");
                    return Ok(());
                };
                // Pin the delivery tx to the message's funded gasLimit so the relayer can claim its
                // fee later (the vault only pays when the proven delivery gasLimit matches a funded
                // tier). `None` (no vault, unfunded message, read error, or read timeout) falls back
                // to estimation. The read is bounded by FUNDED_GAS_READ_TIMEOUT: it runs in this
                // serial worker's critical path, so an unbounded await on a stalled source RPC would
                // wedge the whole route (and starve the cancel branch) — the same hazard RECEIPT_TIMEOUT guards.
                let funded_gas = match (&source_provider, route.relayer_contract_address) {
                    (Some(p), Some(relayer_contract)) => {
                        match tokio::time::timeout(
                            FUNDED_GAS_READ_TIMEOUT,
                            funded_gas_limit(p, relayer_contract, job.message_id),
                        ).await {
                            Ok(Ok(g)) => g,
                            Ok(Err(err)) => {
                                warn!(chain_key, message_id = %job.message_id, %err,
                                    "could not read funded gasLimit; falling back to gas estimation (fee may be unclaimable)");
                                None
                            }
                            Err(_) => {
                                warn!(chain_key, message_id = %job.message_id, timeout_secs = FUNDED_GAS_READ_TIMEOUT.as_secs(),
                                    "funded gasLimit read timed out; falling back to gas estimation (fee may be unclaimable)");
                                None
                            }
                        }
                    }
                    _ => None,
                };
                let outcome = match handle_job(
                    &route,
                    &delivery_config,
                    &provider,
                    signer_address,
                    &broadcast_locks,
                    &job,
                    funded_gas,
                    metrics.as_ref(),
                ).await {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        error!(chain_key, message_id = %job.message_id, %err, "❌ delivery job failed");
                        DeliveryResultKind::Retryable
                    }
                };
                // Job finished (delivered, terminal, or retryable) — real forward progress.
                health.heartbeat(&health_key);
                if result_tx
                    .send(DeliveryResult {
                        chain_key: job.chain_key,
                        message_hash: job.message_hash,
                        outcome,
                    })
                    .await
                    .is_err()
                {
                    warn!(chain_key, "delivery result channel closed; worker exiting");
                    return Ok(());
                }
            }
        }
    }
}

/// Read a message's funded `gasLimit` from the source `RelayerContract` ledger. `Ok(None)` when the
/// message has no funded route (payer unset / gasLimit 0) or the value is out of sane range, so
/// delivery falls back to estimation; `Err` only on an RPC/transport failure (the caller logs and
/// also falls back).
async fn funded_gas_limit<P: Provider>(
    source_provider: &P,
    relayer_contract: Address,
    message_id: B256,
) -> Result<Option<u64>> {
    let ledger = IRelayerContract::new(relayer_contract, source_provider);
    let info = ledger
        .getMessageInfo(message_id)
        .call()
        .await
        .context("RelayerContract.getMessageInfo failed")?;
    if info.gasLimit.is_zero() {
        return Ok(None);
    }
    // Guard against a misconfigured contract address decoding to junk: an absurd gasLimit would
    // otherwise pin an unincludable `.gas()` on every delivery. Ignore it and estimate instead.
    if info.gasLimit > alloy::primitives::U256::from(MAX_FUNDED_GAS) {
        tracing::warn!(%relayer_contract, gas_limit = %info.gasLimit,
            "RelayerContract.getMessageInfo returned an implausible gasLimit; ignoring (will estimate)");
        return Ok(None);
    }
    Ok(Some(info.gasLimit.saturating_to::<u64>()))
}

/// Note on liveness: this function deliberately does **not** heartbeat. The caller's tick cannot
/// fire while this future is awaited from inside its `select!` branch, so a job that retries for
/// longer than [`crate::health::PROGRESS_DEADLINE`] does report the route stale. That is the lesser
/// evil: no signal available in here distinguishes "slow but working" from "permanently wedged", so
/// beating per attempt (or per accepted send) could report a dead route as healthy forever, which is
/// the exact failure class the watchdog exists to catch. The stale-local-nonce instance of that is
/// now fixed at the source (see [`crate::broadcast`]), but an underpriced tx still gets *accepted*
/// into the mempool and never mines, so the reasoning stands. See the PR notes: the worst-case job
/// wall time vs. `PROGRESS_DEADLINE` needs settling before a `livenessProbe` is added to the chart,
/// or a slow destination chain will restart pods that are merely waiting.
#[allow(clippy::too_many_arguments)]
async fn handle_job<P: Provider + Clone + 'static>(
    route: &ChainRoute,
    delivery_config: &DeliveryConfig,
    provider: &P,
    signer_address: Address,
    broadcast_locks: &Arc<crate::broadcast::BroadcastLocks>,
    job: &DeliveryJob,
    funded_gas: Option<u64>,
    metrics: &dyn crate::prom::MetricsTrait,
) -> Result<DeliveryResultKind> {
    let inbox = IInbox::new(route.inbox_address, provider);

    if delivery_config.simulate_before_send {
        // Validity check only — do NOT pin `.gas()` here. The simulate exists to catch
        // `validateVotes` logic reverts; constraining it to the funded gas would conflate an
        // under-funded message (out-of-gas) with a genuine revert and add head-vs-mined-block
        // boundary nondeterminism. Gas is pinned on the real send below.
        if let Err(err) = inbox
            .deliverMessage(
                job.message_id,
                job.emitter,
                Bytes::from(job.payload.clone()),
                Bytes::from(job.votes_calldata.clone()),
            )
            .call()
            .await
        {
            // If the inbox already accepted this message we treat it as success (idempotent —
            // PoC §6.5). Any other *revert* is deterministic, so we don't burn gas. A transport
            // failure (RPC blip, timeout) is neither — the pool retries it with backoff; treating
            // it as terminal would silently drop a deliverable message.
            if revert_already_validated(&err) {
                debug!(chain_key = route.chain_key, message_id = %job.message_id,
                    "simulate detected already-validated; idempotent success");
                metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::AlreadyValidated);
                return Ok(DeliveryResultKind::Delivered);
            }
            if is_revert(&err.to_string()) {
                metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Reverted);
                warn!(
                    chain_key = route.chain_key,
                    message_id = %job.message_id,
                    %err,
                    "simulate(deliverMessage) reverted; treating as terminal"
                );
                return Ok(DeliveryResultKind::Terminal);
            }
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                %err,
                "simulate(deliverMessage) failed at transport level; returning to pool for retry"
            );
            return Ok(DeliveryResultKind::Retryable);
        }
    }

    // Under-funding guard. When we have a funded gasLimit, the send is pinned to it (so the proven
    // delivery gasLimit matches the funded tier and `claimDelivery` can pay). But if the message
    // actually needs MORE gas than was funded, pinning would guarantee an out-of-gas revert —
    // burning the relayer's gas for no claimable delivery. Estimate first; if the funded gas can't
    // cover it, don't submit — return non-terminally so the pool retries (leaving a window for a
    // `topUpGasLimit`) rather than dropping a message that becomes deliverable once topped up.
    if let Some(gas) = funded_gas {
        // Bounded like the getMessageInfo read: this estimate sits on the same serial critical
        // path, so an unbounded await on a stalled destination RPC would wedge the route.
        let est = tokio::time::timeout(
            FUNDED_GAS_READ_TIMEOUT,
            inbox
                .deliverMessage(
                    job.message_id,
                    job.emitter,
                    Bytes::from(job.payload.clone()),
                    Bytes::from(job.votes_calldata.clone()),
                )
                .estimate_gas(),
        )
        .await;
        match est {
            Ok(Ok(est)) if est > gas => {
                warn!(
                    chain_key = route.chain_key,
                    message_id = %job.message_id,
                    estimate = est,
                    funded = gas,
                    "delivery is under-funded — estimated gas exceeds the funded gasLimit; not \
                     delivering (awaiting a topUpGasLimit). Retrying with backoff."
                );
                return Ok(DeliveryResultKind::Retryable);
            }
            // Funded gas covers the estimate — proceed to send pinned at the funded gas.
            Ok(Ok(_)) => {}
            // The estimate itself failed. Classify like the simulate does: when
            // `simulate_before_send` is off, this is where a deterministic revert first surfaces,
            // and blanket-retrying a permanent revert would loop forever. Only genuine transport
            // errors are retryable (we must not send unverified: an under-funded message would
            // OOG and be dropped as terminal — the exact failure this guard exists to prevent).
            Ok(Err(err)) => {
                if revert_already_validated(&err) {
                    debug!(chain_key = route.chain_key, message_id = %job.message_id,
                        "estimate detected already-validated; idempotent success");
                    metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::AlreadyValidated);
                    return Ok(DeliveryResultKind::Delivered);
                }
                if is_revert(&err.to_string()) {
                    metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Reverted);
                    warn!(
                        chain_key = route.chain_key,
                        message_id = %job.message_id,
                        %err,
                        "estimate(deliverMessage) reverted; treating as terminal"
                    );
                    return Ok(DeliveryResultKind::Terminal);
                }
                warn!(
                    chain_key = route.chain_key,
                    message_id = %job.message_id,
                    %err,
                    "could not estimate delivery gas to verify funding (transport); retrying \
                     rather than risking an out-of-gas send on a possibly under-funded message"
                );
                return Ok(DeliveryResultKind::Retryable);
            }
            Err(_elapsed) => {
                warn!(
                    chain_key = route.chain_key,
                    message_id = %job.message_id,
                    timeout_secs = FUNDED_GAS_READ_TIMEOUT.as_secs(),
                    "gas estimate timed out; retrying rather than risking an out-of-gas send"
                );
                return Ok(DeliveryResultKind::Retryable);
            }
        }
    }

    metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Submitted);
    let started = Instant::now();

    let mut backoff = INITIAL_BACKOFF;
    let mut attempts = 0u32;
    let outcome = loop {
        attempts += 1;
        let mut tx = inbox.deliverMessage(
            job.message_id,
            job.emitter,
            Bytes::from(job.payload.clone()),
            Bytes::from(job.votes_calldata.clone()),
        );
        if let Some(gas) = funded_gas {
            tx = tx.gas(gas);
        }
        // `send()` is several RPC round trips (gas, fee, nonce, `eth_sendRawTransaction`) and alloy's
        // HTTP transport sets no timeout, so on a black-holed endpoint this await never returns and
        // parks the route — the same hazard FUNDED_GAS_READ_TIMEOUT and RECEIPT_TIMEOUT guard.
        //
        // Serialized on the signer so the chain-read nonce this send is about to fetch already
        // reflects every earlier broadcast from the same key — including the detached
        // `retryPendingMessage` tasks and the set-update submitter. The guard covers only the
        // broadcast; the receipt is awaited below, outside it, or a single confirmation would block
        // every other sender on the key. Either stall is retryable and consumes no nonce.
        let pending = match broadcast_locks
            .broadcast(signer_address, SEND_TIMEOUT, tx.send())
            .await
        {
            Ok(res) => res,
            Err(stalled) => {
                if attempts <= delivery_config.max_retries {
                    warn!(
                        chain_key = route.chain_key,
                        message_id = %job.message_id,
                        attempts,
                        %stalled,
                        "send did not complete; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
                break SendOutcome::Failed(stalled.to_string());
            }
        };

        match pending {
            // Poll-based receipt wait — alloy's `get_receipt()` heartbeat wedges against
            // Frontier's mixHash-less blocks (see the `receipt` module docs). Sepolia is fine
            // today, but routes are chain-agnostic and a Frontier destination would not be.
            Ok(builder) => {
                match tokio::time::timeout(RECEIPT_TIMEOUT, crate::receipt::await_receipt(&builder))
                    .await
                {
                    Ok(Ok(receipt)) => {
                        if receipt.status() {
                            // `deliverMessage` succeeds even when the dApp callback reverts — the
                            // inbox stores the message and emits `MessagePending` instead of
                            // `MessageDelivered`. Detect that from the receipt logs; it is NOT a
                            // revert (see SimpleInbox.deliverMessage's try/catch).
                            let left_pending = receipt.inner.logs().iter().any(|l| {
                                l.address() == route.inbox_address
                                    && l.topics().first()
                                        == Some(&IInbox::MessagePending::SIGNATURE_HASH)
                            });
                            if left_pending {
                                break SendOutcome::Pending;
                            }
                            break SendOutcome::Succeeded;
                        }
                        // Receipt with `status = false` means the tx mined but reverted. For PoC
                        // we don't decode the revert reason from the receipt — we surface it via
                        // metrics and stop retrying (the next message will get its own attempt).
                        break SendOutcome::Reverted("tx mined but reverted".into());
                    }
                    Ok(Err(err)) if attempts <= delivery_config.max_retries => {
                        warn!(
                            chain_key = route.chain_key,
                            message_id = %job.message_id,
                            attempts,
                            %err,
                            "receipt fetch failed; retrying"
                        );
                    }
                    Ok(Err(err)) => break SendOutcome::Failed(format!("receipt: {err}")),
                    Err(_elapsed) => {
                        // Stuck / underpriced tx: stop blocking the route. The pool retries with
                        // backoff; if this tx mines meanwhile, the next simulate resolves it as
                        // already-validated.
                        break SendOutcome::Failed(format!(
                            "no receipt within {RECEIPT_TIMEOUT:?} (tx possibly stuck)"
                        ));
                    }
                }
            }
            Err(err) if revert_already_validated(&err) => {
                // Lost the race to another relayer (PoC §6.5). Treat as success.
                break SendOutcome::AlreadyValidated;
            }
            Err(err) if is_revert(&err.to_string()) => {
                // Deterministic contract revert at send / gas-estimation time — retrying would
                // revert identically, so don't burn the retry budget on it.
                break SendOutcome::Reverted(err.to_string());
            }
            Err(err) if attempts <= delivery_config.max_retries => {
                warn!(
                    chain_key = route.chain_key,
                    message_id = %job.message_id,
                    attempts,
                    backoff_ms = backoff.as_millis() as u64,
                    %err,
                    "send failed; retrying"
                );
            }
            Err(err) => break SendOutcome::Failed(err.to_string()),
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    };

    match outcome {
        SendOutcome::Succeeded => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Succeeded);
            metrics.observe_time_to_deliver(started.elapsed());
            info!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                signer_count = job.signer_count,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "✅ message delivered"
            );
            Ok(DeliveryResultKind::Delivered)
        }
        SendOutcome::AlreadyValidated => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::AlreadyValidated);
            info!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                "↩️ another relayer already delivered — idempotent success"
            );
            Ok(DeliveryResultKind::Delivered)
        }
        SendOutcome::Pending => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Pending);
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                "⚠️ votes validated but the dApp callback reverted — message left pending; \
                 scheduling bounded retryPendingMessage attempts"
            );
            // The votes are consumed on-chain (`validatedMessages[messageId] = true`), so from the
            // pool's perspective delivery is complete — a re-dispatch would revert as a duplicate.
            // The remaining `retryPendingMessage` work is permissionless best-effort.
            spawn_pending_retry(
                (*provider).clone(),
                signer_address,
                broadcast_locks.clone(),
                *inbox.address(),
                job.message_id,
                route.chain_key,
            );
            Ok(DeliveryResultKind::Delivered)
        }
        SendOutcome::Reverted(reason) => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Reverted);
            error!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                %reason,
                "❌ delivery reverted; no further retries"
            );
            Ok(DeliveryResultKind::Terminal)
        }
        SendOutcome::Failed(err_str) => {
            metrics.inc_deliver_tx(route.chain_key, DeliveryStatus::Reverted);
            warn!(
                chain_key = route.chain_key,
                message_id = %job.message_id,
                err = %err_str,
                "send exhausted delivery worker retries; returning to pool for bounded retry"
            );
            Ok(DeliveryResultKind::Retryable)
        }
    }
}

#[derive(Debug)]
enum SendOutcome {
    Succeeded,
    AlreadyValidated,
    /// Tx succeeded but the receipt carries `MessagePending` — the dApp callback reverted and the
    /// message is stored for `retryPendingMessage`.
    Pending,
    /// Deterministic revert (mined-and-reverted, or revert at send/estimation time).
    Reverted(String),
    /// Transient infrastructure failure — returned to the pool's bounded retry.
    Failed(String),
}

/// Whether a `deliverMessage` error means the inbox already accepted this message (idempotent
/// success — we lost the race to another relayer, or a previous stuck attempt mined).
///
/// Matched three ways because node dialects differ: the deployed `SimpleInbox` rejects duplicates
/// with `require(..., "Already validated")` (a *string* revert), the custom error name covers
/// future inbox versions on nodes that decode names, and the selector covers nodes that return
/// raw revert data (see [`crate::revert`]).
fn revert_already_validated(err: &impl std::fmt::Display) -> bool {
    let s = err.to_string();
    s.contains("Already validated")
        || s.contains("MessageAlreadyValidated")
        || has_selector(&s, IInbox::MessageAlreadyValidated::SELECTOR)
}

/// Bounded, detached best-effort `retryPendingMessage` attempts. Detached because it must not
/// block the route's serial delivery worker; bounded ([`PENDING_RETRY_DELAYS`]) because the call
/// is permissionless — anyone (including a future relayer restart) can retry a message that is
/// still pending, so giving up here strands nothing.
fn spawn_pending_retry<P: Provider + 'static>(
    provider: P,
    signer_address: Address,
    broadcast_locks: Arc<crate::broadcast::BroadcastLocks>,
    inbox_address: Address,
    message_id: B256,
    chain_key: u64,
) {
    tokio::spawn(async move {
        let inbox = IInbox::new(inbox_address, &provider);
        for (attempt, delay) in PENDING_RETRY_DELAYS.iter().enumerate() {
            tokio::time::sleep(*delay).await;
            // Someone (a dApp user, another relayer) may have completed the retry meanwhile.
            match inbox.isPending(message_id).call().await {
                Ok(ret) if !ret => {
                    info!(chain_key, %message_id, "♻️ pending message already resolved");
                    return;
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(chain_key, %message_id, %err, "isPending check failed; attempting retry anyway");
                }
            }
            // Serialized and bounded like the delivery send: this task runs detached but signs with
            // the same key as the worker that spawned it, so an unserialized broadcast here would
            // race the worker for the same chain-read nonce.
            let sent = match broadcast_locks
                .broadcast(
                    signer_address,
                    SEND_TIMEOUT,
                    inbox.retryPendingMessage(message_id).send(),
                )
                .await
            {
                Ok(res) => res,
                Err(stalled) => {
                    warn!(chain_key, %message_id, attempt, %stalled, "retryPendingMessage send did not complete");
                    continue;
                }
            };
            match sent {
                Ok(builder) => {
                    match tokio::time::timeout(
                        RECEIPT_TIMEOUT,
                        crate::receipt::await_receipt(&builder),
                    )
                    .await
                    {
                        Ok(Ok(receipt)) if receipt.status() => {
                            info!(chain_key, %message_id, "♻️ retryPendingMessage succeeded");
                            return;
                        }
                        Ok(Ok(_)) => {
                            warn!(chain_key, %message_id, attempt, "retryPendingMessage tx reverted");
                        }
                        Ok(Err(err)) => {
                            warn!(chain_key, %message_id, attempt, %err, "retryPendingMessage receipt failed");
                        }
                        Err(_) => {
                            warn!(chain_key, %message_id, attempt, "retryPendingMessage receipt timed out");
                        }
                    }
                }
                Err(err) => {
                    warn!(chain_key, %message_id, attempt, %err, "retryPendingMessage send failed");
                }
            }
        }
        warn!(
            chain_key,
            %message_id,
            "retryPendingMessage attempts exhausted; message stays retryable on-chain \
             (permissionless retryPendingMessage)"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_validated_matches_all_dialects() {
        // The deployed SimpleInbox string revert.
        assert!(revert_already_validated(
            &"execution reverted: Already validated"
        ));
        // Decoded custom-error name (future inbox versions).
        assert!(revert_already_validated(
            &"reverted: MessageAlreadyValidated"
        ));
        // Raw selector data (Creditcoin-style node).
        let sel = alloy::hex::encode(IInbox::MessageAlreadyValidated::SELECTOR);
        assert!(revert_already_validated(&format!(
            "VM Exception while processing transaction: revert, data: \"0x{sel}\""
        )));
        // A transport failure is not a duplicate.
        assert!(!revert_already_validated(&"connection refused"));
        // An unrelated revert is not a duplicate either.
        assert!(!revert_already_validated(
            &"execution reverted: VotesBelowThreshold"
        ));
    }
}
