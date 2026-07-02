# write-ability (vendored)

Shared USC write-ability protocol crate: the canonical `messageHash` implementation, the
`MessageVote` / `ReobservationRequest` wire envelopes, gossipsub topic names, the `bytes32`
chain-key encoding, and the `sol!` ABI bindings for the Outbox / Inbox / validator contracts.

## ⚠️ Source of truth & sync contract

This crate is **vendored from the `creditcoin3` repository** (`common/write-ability`), where the
**attestor** builds against it. The attestor and this relayer MUST agree byte-for-byte on:

- `hash::message_hash(..)` — a divergent hash makes every attestor signature unverifiable;
- the SCALE-encoded `MessageVote` / `ReobservationRequest` envelopes — a divergent codec makes
  gossip mutually unintelligible;
- the gossipsub topic strings (`{chain_key}/message-votes/v1`, `{chain_key}/reobservation-requests/v1`);
- the `sol!` event/function/error signatures (a wrong event signature hash silently matches nothing).

When changing anything here, mirror the change in `creditcoin3/common/write-ability` (and vice
versa) **in the same rollout window**, and rely on the golden-vector tests to catch drift: both
repos pin `message_hash` to identical known-answer vectors (`src/hash.rs` tests here,
`message-relayer/tests/golden_hash.rs`, and the attestor's `write_ability` test module in
creditcoin3). If a vector changes on one side only, CI fails on the other side the moment the
crates are re-synced — do not "fix" a vector mismatch by updating the vector; it means the wire
format broke.

Version pins for `alloy`, `parity-scale-codec`, and `sha3` sit on this wire path and are kept
aligned with the creditcoin3 workspace in the root `Cargo.toml`.
