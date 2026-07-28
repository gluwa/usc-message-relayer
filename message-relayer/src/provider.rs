//! Provider construction for transaction-sending workers.
//!
//! Every worker that *sends* transactions must read its nonce from the chain rather than from a
//! local counter. [`chain_nonce_builder`] is the only correct way to get that; see its docs for why
//! the obvious spelling silently does not work.

use alloy::network::Ethereum;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, GasFiller, JoinFill, NonceFiller, SimpleNonceManager,
};
use alloy::providers::{Identity, ProviderBuilder};

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
/// # Why not `ProviderBuilder::new().with_simple_nonce_management()`
///
/// Because it does nothing. That spelling looks obviously right and is silently a no-op:
///
/// * `ProviderBuilder::new()` is `default().with_recommended_fillers()`, and for `Ethereum` the
///   recommended set is `JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller,
///   ChainIdFiller>>>` — where that `NonceFiller` defaults to `CachedNonceManager`.
/// * `with_simple_nonce_management()` calls `self.filler(..)`, which **appends**: the result is
///   `JoinFill<already_has_cached_nonce, NonceFiller<Simple>>`. There is no prepend or replace.
/// * `JoinFill::fill` fills **left first**, and `NonceFiller::status` returns `Finished` as soon as
///   `tx.nonce().is_some()`. So the cached manager fills the nonce and the simple one is skipped
///   for every transaction.
///
/// Nothing warns about this — it compiles, it runs, and the local counter keeps being used. So the
/// stack is composed explicitly here instead, ordering the simple nonce filler in the position the
/// cached one would otherwise occupy.
///
/// # Why chain-read nonces matter here
///
/// With a locally-cached nonce, one failed broadcast (RPC 502, `eth_sendRawTransaction` timeout,
/// load-balancer failover) consumes a nonce that never reaches the mempool. Every later transaction
/// from that signer queues behind the gap, the worker stops making progress, and only a process
/// restart clears it. Re-reading the pending nonce per send costs one `eth_getTransactionCount` and
/// removes that failure mode. It also stops workers that share a signer key from colliding, since
/// they coordinate through the node instead of through independent local counters.
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
