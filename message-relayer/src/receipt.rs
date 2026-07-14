//! Manual transaction-receipt polling.
//!
//! `PendingTransactionBuilder::get_receipt()` registers the transaction with alloy's
//! provider-wide block poller (the "heartbeat"), which fetches and decodes every new block via
//! `eth_getBlockByNumber`. Frontier nodes (Creditcoin) omit the spec-required `mixHash` field
//! from block responses, so that decode fails on every block: the heartbeat error-logs
//! (`failed to fetch block … missing field 'mixHash'`) in a tight retry loop and the
//! confirmation future can never resolve. The node-side fix is gluwa/frontier_2#16; until a
//! runtime built on it is deployed, awaiting receipts must not depend on block decoding.
//!
//! Polling `eth_getTransactionReceipt` directly involves no block decoding, so it works against
//! those nodes — and is no worse against healthy ones. Same "mined = 1 confirmation" semantic
//! as `get_receipt()`.

use std::time::Duration;

use alloy::network::Network;
use alloy::providers::{PendingTransactionBuilder, Provider};
use anyhow::Result;

/// How often to poll for the receipt. Creditcoin produces a block every ~6s and Sepolia every
/// ~12s; 2s keeps the added confirmation latency small without hammering the RPC.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Await the receipt of `pending` by polling `eth_getTransactionReceipt`, never engaging the
/// provider's block-decoding heartbeat (see module docs). Loops until the receipt exists —
/// callers bound it with their own timeout, exactly as they did around `get_receipt()`.
pub async fn await_receipt<N: Network>(
    pending: &PendingTransactionBuilder<N>,
) -> Result<N::ReceiptResponse> {
    let tx_hash = *pending.tx_hash();
    loop {
        if let Some(receipt) = pending.provider().get_transaction_receipt(tx_hash).await? {
            return Ok(receipt);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
