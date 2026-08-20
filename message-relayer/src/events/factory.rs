//! Outbox address resolution.
//!
//! Production: a factory contract on Creditcoin L1 maps `chainKey` → `Outbox` address (PoC PDF
//! §4). PoC: the relayer falls back to the `outbox_address` set on each [`ChainRoute`] when no
//! factory has been deployed yet. The trait is in place so swapping in the real factory is a
//! one-impl change rather than a refactor across modules.

use std::collections::HashMap;
use std::time::Duration;

use alloy::primitives::{address, Address};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::warn;

use crate::abi::IOutboxFactory;
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
/// **Known limitation:** `state` is in-memory only and always starts from genesis — a restart
/// re-scans full history rather than resuming a persisted cursor (slower, not incorrect).
/// `route.start_block` is deliberately not reused here: it backfills `MessagePublished` on the
/// Outbox, a different contract's history, and could seed the scan after the very `OutboxCreated`
/// it needs to find.
///
/// `state`'s lock is held across every RPC call in a `resolve()` invocation (simplest way to keep
/// a chain_key's scan progress consistent across its chunk loop) — a caller sharing this resolver
/// with another route worker (see `lib.rs`'s resolver selection) waits behind it. Bounded by
/// [`PRECOMPILE_CALL_TIMEOUT`]/[`BLOCK_NUMBER_TIMEOUT`]/[`GET_LOGS_TIMEOUT`] on every call, so that
/// wait is minutes at worst, never indefinite.
#[derive(Debug, Default)]
pub struct FactoryResolver {
    state: Mutex<HashMap<u64, ScanState>>,
}

impl FactoryResolver {
    pub fn new() -> Self {
        Self::default()
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
        let scan = states.entry(chain_key).or_default();
        if scan.factory != factory {
            // New factory (or first resolution): scan its history from scratch, always genesis.
            *scan = ScanState {
                factory,
                scanned_to: 0,
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
}
