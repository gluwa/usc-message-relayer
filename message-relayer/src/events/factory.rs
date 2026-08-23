//! Outbox address resolution.
//!
//! Production: a factory contract on Creditcoin L1 maps `chainKey` → `Outbox` address (PoC PDF
//! §4). PoC: the relayer falls back to the `outbox_address` set on each [`ChainRoute`] when no
//! factory has been deployed yet. The trait is in place so swapping in the real factory is a
//! one-impl change rather than a refactor across modules.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{address, Address};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::abi::IOutboxFactory;
use crate::checkpoint::{CheckpointStore, FactoryScan};
use crate::config::ChainRoute;
use write_ability::protocol::chain_key_to_bytes32;

/// What [`OutboxResolver::resolve`] found: the Outbox address to use, and — when known — the
/// block at which that Outbox became current. A caller switching to a newly-resolved address
/// (an Outbox rotation) uses `current_since_block` to resume `MessagePublished` discovery exactly
/// there instead of guessing "now" and risking a gap between the switch and the Outbox actually
/// going live.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedOutbox {
    pub address: Address,
    pub current_since_block: Option<u64>,
}

/// Pluggable strategy for resolving an Outbox address for a given route. Called once at startup
/// and periodically thereafter (see `events::watch_outbox`), so a rotation is picked up without a
/// restart — implementations should make a call with nothing new to report cheap.
#[async_trait]
pub trait OutboxResolver: Send + Sync + std::fmt::Debug {
    async fn resolve(&self, route: &ChainRoute, provider: &DynProvider) -> Result<ResolvedOutbox>;
}

/// PoC default: take whatever the operator put in `route.outbox_address` and refuse to start
/// otherwise. Used for any route with an explicit `outbox_address`; routes without one use
/// [`FactoryResolver`] (see `message-relayer::lib`'s resolver selection).
#[derive(Debug, Default)]
pub struct ConfigOverrideResolver;

#[async_trait]
impl OutboxResolver for ConfigOverrideResolver {
    async fn resolve(&self, route: &ChainRoute, _provider: &DynProvider) -> Result<ResolvedOutbox> {
        let address = route.outbox_address.with_context(|| {
            format!(
                "chain_key {} has no outbox_address and no factory-based resolution requested — \
                 set `outbox_address` in the route config",
                route.chain_key
            )
        })?;
        Ok(ResolvedOutbox {
            address,
            current_since_block: None,
        })
    }
}

sol! {
    /// `ChainInfoPrecompile` on Creditcoin L1 (creditcoin3 `precompiles/chain-info`, registered at
    /// `AddressU64<4051>` in `runtime/src/precompiles.rs`) — a runtime precompile, not a
    /// usc-contracts artifact, so the `abi_surface` drift gate cannot check this binding; keep it
    /// in sync with creditcoin3 by hand. Confirmed against `precompiles/metadata/abi/chain_info.json`
    /// on branch `writeability-off-usc-dev` (Aug 2026) — not yet on `main`/`usc-dev`.
    #[sol(rpc)]
    #[derive(Debug)]
    contract IChainInfo {
        /// The factory contract governing `chainKey`, from
        /// `pallet_supported_chains::OutboxFactories`. `exists = false` (with `factoryAddr` the
        /// zero address) when nothing is registered for `chainKey`.
        function get_outbox_factory_address(uint64 chainKey)
            external
            view
            returns (address factoryAddr, bool exists);
    }
}

/// `ChainInfoPrecompile`'s fixed address (`AddressU64<4051>` = 4051 decimal = `0xfd3`).
const CHAIN_INFO_PRECOMPILE: Address = address!("0000000000000000000000000000000000000fd3");

/// Maximum block span per `eth_getLogs` chunk — mirrors `events::MAX_BLOCKS_PER_SCAN` /
/// `ack::MAX_BLOCKS_PER_SCAN`; bounded chunks advance the cursor incrementally instead of asking
/// an RPC for a range larger than it will serve.
const MAX_BLOCKS_PER_SCAN: u64 = 2_000;

/// Chunks processed per [`FactoryResolver::resolve`] call. Bounds one call's latency on a cold
/// start against a long block-range backlog; progress persists in `state`, so the next call (the
/// periodic re-resolution in `events::watch_outbox`, or a startup-bootstrap retry) resumes exactly
/// where this one stopped instead of rescanning.
const MAX_SCAN_CHUNKS_PER_CALL: usize = 20;

/// Bounds every individual RPC/precompile call this resolver makes (mirrors
/// `delivery::FUNDED_GAS_READ_TIMEOUT` — a single chain read, not a tx wait). Without it a
/// black-holed provider would hang `resolve()` forever while it holds `state`'s lock, wedging
/// every other caller sharing this resolver (`events::watch_outbox` and `ack::run` share one
/// `FactoryResolver` per route). Applied per call rather than once around the whole function so a
/// slow-but-alive provider can still make multiple chunks of progress in one `resolve()` call.
/// Split per call by expected cost: a plain block-number read is cheap and should fail fast;
/// `eth_getLogs` over up to `MAX_BLOCKS_PER_SCAN` blocks is the most expensive of the three and
/// gets the most headroom.
const PRECOMPILE_CALL_TIMEOUT: Duration = Duration::from_secs(20);
const BLOCK_NUMBER_TIMEOUT: Duration = Duration::from_secs(10);
const GET_LOGS_TIMEOUT: Duration = Duration::from_secs(30);

/// Env override for whether a detected factory rotation resumes the new factory's `OutboxCreated`
/// scan from the old factory's already-reached cursor, instead of rescanning from genesis. See
/// [`FactoryResolver::resolve`]'s doc for the reasoning; default `true`.
const ROTATION_RESUME_FROM_CHECKPOINT_ENV: &str = "RELAYER_FACTORY_ROTATION_RESUME_FROM_CHECKPOINT";

/// Per-`chain_key` scan progress, cached across [`FactoryResolver::resolve`] calls.
#[derive(Debug, Clone, Copy, Default)]
struct ScanState {
    /// Factory this progress applies to; a mismatch against a freshly-resolved factory means it's
    /// for a different log stream and must be discarded (handled in `resolve`).
    factory: Address,
    /// Highest block scanned so far (inclusive); the next scan starts at `scanned_to + 1`.
    scanned_to: u64,
    /// The latest `OutboxCreated` match found so far — its Outbox address, and `(block, log_index)`
    /// so "latest wins" is well-defined even when a permissionless redeploy lands in the same
    /// block as an earlier one.
    current: Option<(Address, u64, u64)>,
}

impl ScanState {
    /// Record an `OutboxCreated` match at `(block, log_index)`, keeping it only if it is more
    /// recent than whatever is already recorded — order-independent, so it does not matter what
    /// order a chunk's logs (or successive chunks) arrive in.
    fn record_if_latest(&mut self, address: Address, block: u64, log_index: u64) {
        let wins = match self.current {
            Some((_, cur_block, cur_index)) => (block, log_index) > (cur_block, cur_index),
            None => true,
        };
        if wins {
            self.current = Some((address, block, log_index));
        }
    }
}

/// The [`ScanState::scanned_to`] to assign when starting a fresh scan of a newly-detected factory:
/// `previous_scanned_to - 1` (the block height already reached under whatever this chain_key's
/// scan was tracking before — a persisted checkpoint recorded against a different factory, or the
/// in-memory state just before a mid-process rotation) when `resume_from_checkpoint` is set,
/// genesis (0) otherwise. Pure so the resume-vs-genesis decision is unit-testable without a live
/// provider.
///
/// The `- 1` matters: `scanned_to` means "scanned through this block, inclusive" and the next chunk
/// starts at `scanned_to + 1`, so assigning `previous_scanned_to` verbatim would skip that boundary
/// block on the new factory's log stream entirely — mirrors `events::outbox_rotation_is_safe`'s
/// identical `saturating_sub(1)` treatment of `current_since_block` for the same reason.
///
/// Resuming from near that height (rather than genesis) is an intentional trade: nothing strictly
/// before it could have driven any delivery through the not-yet-current new Outbox, so a real
/// "just rotated to" `OutboxCreated` is always at or after it. The risk is a permissionless
/// `deployOutbox` on the new factory that predates that height (a mirror/pre-deployed Outbox, as
/// opposed to one created as part of the rotation itself) — that event would never be found.
/// `false` restores the original always-genesis behavior for operators who need that guarantee.
fn rotation_scan_start(previous_scanned_to: u64, resume_from_checkpoint: bool) -> u64 {
    if resume_from_checkpoint {
        previous_scanned_to.saturating_sub(1)
    } else {
        0
    }
}

/// Production resolver: finds the Outbox for `route.chain_key` entirely from on-chain state, no
/// operator-supplied address — mirroring creditcoin3's own attestor-fleet resolver, which avoids a
/// configured factory address on the same grounds ("an address supplied separately from the chain
/// key may not correspond to it").
///
///  1. `get_outbox_factory_address(chainKey)` on [`CHAIN_INFO_PRECOMPILE`] — the factory governing
///     this chain key.
///  2. Scan that factory's `OutboxCreated` logs for `chainKey`, latest by block order wins —
///     `deployOutbox` is permissionless, so more than one may exist over time.
///
/// Called both once at startup and periodically thereafter; progress is cached per `chain_key` in
/// `state`. Only returns `Ok` once fully caught up to that call's confirmed tip, never an
/// early/not-yet-final match — a more recent `OutboxCreated` could still be sitting unscanned.
///
/// `route.start_block` is deliberately not reused to seed a fresh scan: it backfills
/// `MessagePublished` on the Outbox, a different contract's history, and could start the scan
/// after the very `OutboxCreated` it needs to find.
///
/// When `checkpoint` is `Some`, a chain_key's scan progress (cursor + winner found so far, see
/// [`FactoryScan`]) is persisted after every call and reloaded the first time that chain_key is
/// seen in this process — so a restart resumes the scan instead of rescanning from genesis.
///
/// A persisted (or in-memory) scan recorded against a factory other than the one freshly resolved
/// — an Outbox-factory rotation, observed either while the relayer was down or while it was
/// running — resumes the *new* factory's scan from the *old* one's already-reached cursor rather
/// than genesis, when [`ROTATION_RESUME_FROM_CHECKPOINT_ENV`] is enabled (default; see
/// [`rotation_scan_start`]). Without that env var (or with it disabled), a rotation always
/// rescans the new factory from genesis — safe, but a full-history `eth_getLogs` scan on both the
/// rotate and the eventual restore, which on a long-lived chain can take minutes even though
/// nothing before the old factory's cursor could have driven a delivery through the not-yet-current
/// new outbox. `checkpoint: None` keeps the old in-memory-only behaviour (used in tests and when
/// persistence is disabled entirely) but still honors the rotation-resume setting.
///
/// `state`'s lock is held across every RPC call in a `resolve()` invocation (simplest way to keep
/// a chain_key's scan progress consistent across its chunk loop) — a caller sharing this resolver
/// with another route worker (see `lib.rs`'s resolver selection) waits behind it. Bounded by
/// [`PRECOMPILE_CALL_TIMEOUT`]/[`BLOCK_NUMBER_TIMEOUT`]/[`GET_LOGS_TIMEOUT`] on every call, so that
/// wait is minutes at worst, never indefinite.
#[derive(Debug, Default)]
pub struct FactoryResolver {
    state: Mutex<HashMap<u64, ScanState>>,
    checkpoint: Option<Arc<CheckpointStore>>,
    /// Cached once at construction (see [`ROTATION_RESUME_FROM_CHECKPOINT_ENV`]) rather than
    /// re-read on every `resolve()` call — this only needs to change with a restart.
    resume_rotation_from_checkpoint: bool,
}

impl FactoryResolver {
    pub fn new(checkpoint: Option<Arc<CheckpointStore>>) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            checkpoint,
            resume_rotation_from_checkpoint: crate::config::bool_env_override(
                ROTATION_RESUME_FROM_CHECKPOINT_ENV,
                true,
            ),
        }
    }

    /// The checkpoint-store key this resolver persists `chain_key`'s scan progress under.
    fn checkpoint_key(chain_key: u64) -> String {
        format!("factory:{chain_key}")
    }

    /// The [`ScanState`] to start a fresh-in-this-process scan of `factory` with, given whatever
    /// was previously persisted for this chain_key (if anything). Pulled out of `resolve` as a
    /// pure function so the resume-vs-discard decision is unit-testable without a live provider.
    ///
    /// `persisted` is reused verbatim only when it was recorded against this same `factory`. A
    /// mismatch (an Outbox-factory rotation that happened while the relayer was down) resumes from
    /// the persisted cursor's height when `resume_from_checkpoint` is set (see
    /// [`rotation_scan_start`]), exactly like the in-memory `scan.factory != factory` check in
    /// `resolve` does for a rotation observed while running; otherwise it restarts from genesis,
    /// same as "nothing persisted".
    fn initial_scan_state(
        factory: Address,
        persisted: Option<&FactoryScan>,
        resume_from_checkpoint: bool,
    ) -> ScanState {
        match persisted {
            Some(persisted) if persisted.factory == factory.to_string() => ScanState {
                factory,
                scanned_to: persisted.scanned_to,
                current: persisted
                    .winner
                    .as_ref()
                    .and_then(|(address, block, log_index)| {
                        address
                            .parse::<Address>()
                            .ok()
                            .map(|a| (a, *block, *log_index))
                    }),
            },
            Some(persisted) => ScanState {
                factory,
                scanned_to: rotation_scan_start(persisted.scanned_to, resume_from_checkpoint),
                current: None,
            },
            None => ScanState {
                factory,
                scanned_to: 0,
                current: None,
            },
        }
    }
}

#[async_trait]
impl OutboxResolver for FactoryResolver {
    async fn resolve(&self, route: &ChainRoute, provider: &DynProvider) -> Result<ResolvedOutbox> {
        let chain_key = route.chain_key;

        let chain_info = IChainInfo::new(CHAIN_INFO_PRECOMPILE, provider);
        let factory_result = tokio::time::timeout(
            PRECOMPILE_CALL_TIMEOUT,
            chain_info.get_outbox_factory_address(chain_key).call(),
        )
        .await
        .with_context(|| {
            format!(
                "chain_key {chain_key}: get_outbox_factory_address precompile call timed out \
                 after {PRECOMPILE_CALL_TIMEOUT:?}"
            )
        })?
        .with_context(|| {
            format!("chain_key {chain_key}: get_outbox_factory_address precompile call failed")
        })?;
        if !factory_result.exists || factory_result.factoryAddr.is_zero() {
            anyhow::bail!(
                "chain_key {chain_key} has no OutboxFactory registered on-chain \
                 (pallet supportedChains.OutboxFactories is empty for this key)"
            );
        }
        let factory = factory_result.factoryAddr;

        let mut states = self.state.lock().await;
        let first_use_in_process = !states.contains_key(&chain_key);
        let scan = states.entry(chain_key).or_default();

        if first_use_in_process {
            let persisted = self
                .checkpoint
                .as_ref()
                .and_then(|cp| cp.get_factory_scan(&Self::checkpoint_key(chain_key)));
            match &persisted {
                Some(p) if p.factory == factory.to_string() => info!(
                    chain_key,
                    %factory,
                    scanned_to = p.scanned_to,
                    winner = ?p.winner,
                    "↩️ resuming OutboxCreated discovery from persisted factory-scan checkpoint"
                ),
                Some(p) => info!(
                    chain_key,
                    %factory,
                    persisted_factory = %p.factory,
                    "factory-scan checkpoint is recorded against a different factory (rotated \
                     while down); discarding it and scanning from genesis"
                ),
                None => {}
            }
            *scan = Self::initial_scan_state(
                factory,
                persisted.as_ref(),
                self.resume_rotation_from_checkpoint,
            );
        }

        if scan.factory != factory {
            // Factory rotation observed mid-process (not just at startup): scan the new factory's
            // history starting from the old factory's cursor (default) or from genesis — see
            // `rotation_scan_start` and the doc on `resolve` above.
            let resume_from =
                rotation_scan_start(scan.scanned_to, self.resume_rotation_from_checkpoint);
            info!(
                chain_key,
                old_factory = %scan.factory,
                new_factory = %factory,
                resume_from,
                resume_from_checkpoint = self.resume_rotation_from_checkpoint,
                "🔁 factory rotation detected mid-process; restarting OutboxCreated discovery on \
                 the new factory"
            );
            *scan = ScanState {
                factory,
                scanned_to: resume_from,
                current: None,
            };
        }

        let tip = tokio::time::timeout(BLOCK_NUMBER_TIMEOUT, provider.get_block_number())
            .await
            .with_context(|| {
                format!(
                    "chain_key {chain_key}: reading chain head timed out after \
                     {BLOCK_NUMBER_TIMEOUT:?}"
                )
            })?
            .with_context(|| format!("chain_key {chain_key}: failed to read chain head"))?;
        let confirmed = tip.saturating_sub(route.block_confirmation_depth);

        let mut chunks = 0;
        while scan.scanned_to < confirmed && chunks < MAX_SCAN_CHUNKS_PER_CALL {
            let from_block = scan.scanned_to + 1;
            let to_block = confirmed.min(scan.scanned_to.saturating_add(MAX_BLOCKS_PER_SCAN));

            let filter = Filter::new()
                .address(factory)
                .event_signature(IOutboxFactory::OutboxCreated::SIGNATURE_HASH)
                .topic2(chain_key_to_bytes32(chain_key))
                .from_block(from_block)
                .to_block(to_block);

            let logs = tokio::time::timeout(GET_LOGS_TIMEOUT, provider.get_logs(&filter))
                .await
                .with_context(|| {
                    format!(
                        "chain_key {chain_key}: eth_getLogs OutboxCreated on factory {factory} \
                         from {from_block} to {to_block} timed out after {GET_LOGS_TIMEOUT:?}"
                    )
                })?
                .with_context(|| {
                    format!(
                        "chain_key {chain_key}: eth_getLogs OutboxCreated on factory {factory} \
                         from {from_block} to {to_block} failed"
                    )
                })?;

            for log in logs {
                let (Some(block), Some(log_index)) = (log.block_number, log.log_index) else {
                    warn!(
                        chain_key,
                        %factory,
                        "OutboxCreated log missing block number or log index; skipping"
                    );
                    continue;
                };
                match IOutboxFactory::OutboxCreated::decode_log(&log.inner) {
                    Ok(decoded) => {
                        scan.record_if_latest(decoded.data.outbox, block, log_index);
                    }
                    Err(err) => {
                        warn!(chain_key, %factory, %err, "could not decode OutboxCreated log; skipping");
                    }
                }
            }

            scan.scanned_to = to_block;
            chunks += 1;
        }

        if let Some(cp) = &self.checkpoint {
            let to_persist = FactoryScan {
                factory: factory.to_string(),
                scanned_to: scan.scanned_to,
                winner: scan
                    .current
                    .map(|(address, block, log_index)| (address.to_string(), block, log_index)),
            };
            if let Err(err) = cp.set_factory_scan(&Self::checkpoint_key(chain_key), &to_persist) {
                warn!(chain_key, %err, "failed to persist factory-resolver scan checkpoint");
            }
        }

        if scan.scanned_to < confirmed {
            // Not yet caught up to the confirmed tip — a match found so far could still be
            // superseded by a more recent one further ahead. Bail so the caller retries, resuming
            // this cursor rather than rescanning.
            anyhow::bail!(
                "chain_key {chain_key}: still scanning OutboxCreated backlog on factory {factory} \
                 ({} of {confirmed} blocks); resolution not final yet",
                scan.scanned_to
            );
        }

        match scan.current {
            Some((address, block, _)) => Ok(ResolvedOutbox {
                address,
                current_since_block: Some(block),
            }),
            None => anyhow::bail!(
                "chain_key {chain_key}: no OutboxCreated event found for factory {factory} \
                 (scanned fully to block {confirmed}); this chain_key has no deployed Outbox yet"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AttestorSet, ChainRoute};
    use alloy::providers::ProviderBuilder;

    fn route_with(outbox: Option<Address>) -> ChainRoute {
        ChainRoute {
            chain_key: 2,
            creditcoin_chain_id: 1,
            outbox_address: outbox,
            destination_rpc_url: "http://x".into(),
            inbox_address: address!("0000000000000000000000000000000000000002"),
            signer_key: None,
            relayer_contract_address: None,
            block_confirmation_depth: 0,
            start_block: None,
            attestor_set: AttestorSet::Static(vec![address!(
                "000000000000000000000000000000000000000a"
            )]),
            threshold_override: None,
            ack: None,
            claim: None,
        }
    }

    /// A `DynProvider` that is never actually called — `ConfigOverrideResolver` ignores its
    /// provider argument entirely, so this only needs to type-check, not connect.
    fn unused_provider() -> DynProvider {
        ProviderBuilder::new()
            .connect_http("http://127.0.0.1:1".parse().unwrap())
            .erased()
    }

    #[tokio::test]
    async fn config_override_returns_set_value() {
        let r = ConfigOverrideResolver;
        let addr = address!("0000000000000000000000000000000000000099");
        let out = r
            .resolve(&route_with(Some(addr)), &unused_provider())
            .await
            .unwrap();
        assert_eq!(out.address, addr);
        assert_eq!(out.current_since_block, None);
    }

    #[tokio::test]
    async fn config_override_fails_without_value() {
        let r = ConfigOverrideResolver;
        let err = r
            .resolve(&route_with(None), &unused_provider())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outbox_address"));
    }

    #[test]
    fn chain_info_precompile_address_matches_creditcoin3_registration() {
        // AddressU64<4051> per creditcoin3 runtime/src/precompiles.rs: the low 8 bytes of the
        // 20-byte address hold the u64 value big-endian, the rest zero. 4051 decimal = 0xfd3.
        let mut bytes = [0u8; 20];
        bytes[12..20].copy_from_slice(&4051u64.to_be_bytes());
        assert_eq!(CHAIN_INFO_PRECOMPILE, Address::from(bytes));
    }

    /// "Latest wins" tie-break: `(block, log_index)` ordering, not insertion order — a permissionless
    /// redeploy landing in the same block as an earlier one must still resolve deterministically
    /// to the higher log index, regardless of the order `eth_getLogs` happens to return them in.
    #[test]
    fn scan_state_latest_wins_by_block_then_log_index() {
        let a = address!("0000000000000000000000000000000000000001");
        let b = address!("0000000000000000000000000000000000000002");
        let c = address!("0000000000000000000000000000000000000003");

        let mut scan = ScanState::default();
        // Processing order deliberately does not match log_index order — the winner must be
        // decided by (block, log_index), not by arrival order.
        scan.record_if_latest(a, 10, 0);
        scan.record_if_latest(c, 10, 2);
        scan.record_if_latest(b, 10, 1);
        // Highest log_index within the same block wins, regardless of processing order.
        assert_eq!(scan.current, Some((c, 10, 2)));

        // A later block always beats an earlier one, even at log_index 0.
        scan.record_if_latest(a, 11, 0);
        assert_eq!(scan.current, Some((a, 11, 0)));

        // An earlier (block, log_index) than the current winner must not overwrite it.
        scan.record_if_latest(b, 10, 5);
        assert_eq!(scan.current, Some((a, 11, 0)));
    }

    /// No persisted checkpoint at all (first boot, or persistence disabled): start from genesis
    /// regardless of the rotation-resume setting — there is no cursor to resume from.
    #[test]
    fn initial_scan_state_with_nothing_persisted_starts_from_genesis() {
        let factory = address!("0000000000000000000000000000000000000001");
        for resume_from_checkpoint in [true, false] {
            let scan = FactoryResolver::initial_scan_state(factory, None, resume_from_checkpoint);
            assert_eq!(scan.factory, factory);
            assert_eq!(scan.scanned_to, 0);
            assert_eq!(scan.current, None);
        }
    }

    /// A checkpoint persisted against this same factory resumes exactly where it left off,
    /// winner included — the entire point of persisting it. Not a rotation, so the resume setting
    /// is irrelevant here.
    #[test]
    fn initial_scan_state_resumes_when_factory_matches() {
        let factory = address!("0000000000000000000000000000000000000001");
        let winner = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: factory.to_string(),
            scanned_to: 12_345,
            winner: Some((winner.to_string(), 100, 3)),
        };
        let scan = FactoryResolver::initial_scan_state(factory, Some(&persisted), true);
        assert_eq!(scan.factory, factory);
        assert_eq!(scan.scanned_to, 12_345);
        assert_eq!(scan.current, Some((winner, 100, 3)));
    }

    /// A checkpoint persisted against a *different* factory (rotation while the relayer was down),
    /// with the default resume-from-checkpoint behavior enabled: resume the new factory's scan
    /// from just before the old one's cursor instead of genesis, so the boundary block itself is
    /// still scanned on the new factory rather than skipped — the winner does NOT carry over (it
    /// belongs to the old factory's log stream), but the scanned height does.
    #[test]
    fn initial_scan_state_resumes_from_checkpoint_for_a_different_factory_by_default() {
        let old_factory = address!("0000000000000000000000000000000000000001");
        let new_factory = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: old_factory.to_string(),
            scanned_to: 12_345,
            winner: Some((
                address!("0000000000000000000000000000000000000003").to_string(),
                100,
                3,
            )),
        };
        let scan = FactoryResolver::initial_scan_state(new_factory, Some(&persisted), true);
        assert_eq!(scan.factory, new_factory);
        assert_eq!(scan.scanned_to, 12_344);
        assert_eq!(scan.current, None);
    }

    /// Same rotation-while-down scenario, but with the resume setting disabled: restart from
    /// genesis — the conservative behavior, for operators who need the guarantee that a
    /// permissionless `deployOutbox` predating the old factory's cursor is still found.
    #[test]
    fn initial_scan_state_discards_checkpoint_for_a_different_factory_when_resume_disabled() {
        let old_factory = address!("0000000000000000000000000000000000000001");
        let new_factory = address!("0000000000000000000000000000000000000002");
        let persisted = FactoryScan {
            factory: old_factory.to_string(),
            scanned_to: 12_345,
            winner: Some((
                address!("0000000000000000000000000000000000000003").to_string(),
                100,
                3,
            )),
        };
        let scan = FactoryResolver::initial_scan_state(new_factory, Some(&persisted), false);
        assert_eq!(scan.factory, new_factory);
        assert_eq!(scan.scanned_to, 0);
        assert_eq!(scan.current, None);
    }

    /// A checkpoint persisted with no winner yet (scanned some of the range, found nothing) still
    /// resumes the cursor — there is nothing to carry forward as `current`, but the scanned range
    /// itself must not be rescanned.
    #[test]
    fn initial_scan_state_resumes_cursor_with_no_winner_yet() {
        let factory = address!("0000000000000000000000000000000000000001");
        let persisted = FactoryScan {
            factory: factory.to_string(),
            scanned_to: 2_000,
            winner: None,
        };
        let scan = FactoryResolver::initial_scan_state(factory, Some(&persisted), true);
        assert_eq!(scan.scanned_to, 2_000);
        assert_eq!(scan.current, None);
    }

    /// `rotation_scan_start` is the pure decision `initial_scan_state` and the mid-process rotation
    /// branch in `resolve` both delegate to: resume just before the old cursor when enabled (so the
    /// boundary block is scanned on the new factory, not skipped), else genesis.
    #[test]
    fn rotation_scan_start_resumes_or_restarts_from_genesis() {
        assert_eq!(rotation_scan_start(691_905, true), 691_904);
        assert_eq!(rotation_scan_start(691_905, false), 0);
        assert_eq!(rotation_scan_start(0, true), 0);
    }
}
