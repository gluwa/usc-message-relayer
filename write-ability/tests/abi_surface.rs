//! Solidity ↔ Rust ABI-surface drift detector (relayer side).
//!
//! `src/abi.rs` is a hand-maintained `sol!` mirror of the usc-contracts surface the relayer calls.
//! The golden vectors police creditcoin3↔relayer agreement, but nothing enforced Solidity↔Rust
//! agreement — and that drift is quiet: a renamed *error* doesn't break anything visibly, it just
//! turns the revert classifier's selector match into dead code (found here: the Outbox renamed
//! `MessageDoesNotRequireAck` → `MessageCannotBeAcknowledged` and the terminal-revert naming kept
//! matching the old selector), and a changed *event* signature moves topic0 so a log filter goes
//! silent instead of failing.
//!
//! For every mirrored function, event and error, recompute the selector / topic0 from the Rust
//! `sol!` types and assert a byte-identical one exists in the compiled hardhat artifact. For the
//! two struct-returning calls the selector alone can't protect (`getMessage`, `getMessageInfo` —
//! outputs aren't part of the selector), also pin the artifact's output tuple against the Rust
//! struct layout, since a reordered field decodes silently into garbage.
//!
//! Runs wherever `USC_CONTRACTS_DIR` points at a compiled usc-contracts checkout; without the env
//! var it is a no-op so plain `cargo test` stays green. creditcoin3's write-ability-e2e workflow
//! (which checks out both this repo and usc-contracts) is the CI home for this check.

use alloy::primitives::keccak256;
use alloy::sol_types::{SolCall, SolError, SolEvent};
use std::path::{Path, PathBuf};
use write_ability::abi::{
    IAcknowledgmentValidator, IInbox, IOutbox, IOutboxFactory, IRelayerContract, IVoteValidator,
};

/// Canonical ABI type for one artifact input/output, expanding structs: `tuple` →
/// `(comp1,comp2,…)`, preserving array suffixes (`tuple[]` → `(…)[]`).
fn canonical_type(param: &serde_json::Value) -> String {
    let ty = param["type"].as_str().expect("abi param has a type");
    if let Some(suffix_start) = ty.find("tuple").map(|_| "tuple".len()) {
        if ty.starts_with("tuple") {
            let components = param["components"]
                .as_array()
                .expect("tuple param has components")
                .iter()
                .map(canonical_type)
                .collect::<Vec<_>>()
                .join(",");
            return format!("({components}){}", &ty[suffix_start..]);
        }
    }
    ty.to_string()
}

fn canonical_signature(entry: &serde_json::Value) -> String {
    let name = entry["name"].as_str().expect("abi entry has a name");
    let params = entry["inputs"]
        .as_array()
        .expect("abi entry has inputs")
        .iter()
        .map(canonical_type)
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({params})")
}

struct Artifact {
    path: PathBuf,
    abi: Vec<serde_json::Value>,
}

impl Artifact {
    fn load(contracts: &Path, rel: &str) -> Self {
        let path = contracts.join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let artifact: serde_json::Value = serde_json::from_str(&raw).expect("artifact is JSON");
        let abi = artifact["abi"]
            .as_array()
            .expect("artifact has an abi array")
            .clone();
        Self { path, abi }
    }

    fn signatures(&self, kind: &str) -> Vec<String> {
        self.abi
            .iter()
            .filter(|entry| entry["type"] == kind)
            .map(canonical_signature)
            .collect()
    }

    /// Assert some declared item of `kind` hashes to `selector_or_topic0` (4 bytes for
    /// functions/errors, 32 for events).
    fn assert_mirrored(&self, kind: &str, rust_signature: &str, hash_prefix: &[u8]) {
        let declared = self.signatures(kind);
        let found = declared
            .iter()
            .any(|sig| keccak256(sig.as_bytes()).0.starts_with(hash_prefix));
        assert!(
            found,
            "{kind} mirror drifted from {}: Rust binds `{rust_signature}` (hash prefix 0x{}), the \
             artifact declares {declared:?}. Update src/abi.rs — and every selector/topic match \
             that uses it — to the contract's current shape.",
            self.path.display(),
            alloy::hex::encode(hash_prefix),
        );
    }

    /// Pin the output tuple of a struct-returning view: selectors don't cover outputs, and a
    /// reordered/retyped field decodes silently into garbage instead of failing.
    fn assert_output_tuple(&self, function: &str, expected: &str) {
        let entry = self
            .abi
            .iter()
            .find(|e| e["type"] == "function" && e["name"] == function)
            .unwrap_or_else(|| panic!("{function} not found in {}", self.path.display()));
        let outputs = entry["outputs"]
            .as_array()
            .expect("function has outputs")
            .iter()
            .map(canonical_type)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            outputs,
            expected,
            "{function} output drifted in {} — the Rust struct in src/abi.rs decodes this shape \
             positionally and must be updated field-for-field",
            self.path.display(),
        );
    }
}

#[test]
fn mirrored_abi_surface_matches_compiled_contracts() {
    let Ok(dir) = std::env::var("USC_CONTRACTS_DIR") else {
        eprintln!(
            "USC_CONTRACTS_DIR not set — skipping ABI-surface check (point it at a compiled \
             usc-contracts checkout to enable)"
        );
        return;
    };
    let contracts = Path::new(&dir).join("artifacts/contracts/write-ability");
    assert!(
        contracts.is_dir(),
        "USC_CONTRACTS_DIR is set but {} does not exist — run `npx hardhat compile` there first",
        contracts.display()
    );

    // --- Outbox (source chain) ---
    let outbox = Artifact::load(&contracts, "Outbox.sol/Outbox.json");
    outbox.assert_mirrored(
        "event",
        IOutbox::MessagePublished::SIGNATURE,
        &IOutbox::MessagePublished::SIGNATURE_HASH.0,
    );
    outbox.assert_mirrored(
        "function",
        "messageCanAck(bytes32)",
        &IOutbox::messageCanAckCall::SELECTOR,
    );
    outbox.assert_mirrored(
        "function",
        "isAcknowledged(bytes32)",
        &IOutbox::isAcknowledgedCall::SELECTOR,
    );
    outbox.assert_mirrored(
        "function",
        "getMessage(bytes32)",
        &IOutbox::getMessageCall::SELECTOR,
    );
    outbox.assert_output_tuple("getMessage", "(address,uint64,uint64,bool,bool,bytes32)");
    outbox.assert_mirrored(
        "error",
        "MessageCannotBeAcknowledged(bytes32)",
        &IOutbox::MessageCannotBeAcknowledged::SELECTOR,
    );
    outbox.assert_mirrored(
        "error",
        "MessageNotFound(bytes32)",
        &IOutbox::MessageNotFound::SELECTOR,
    );
    outbox.assert_mirrored(
        "error",
        "MessageAlreadyAcknowledged(bytes32)",
        &IOutbox::MessageAlreadyAcknowledged::SELECTOR,
    );

    // --- Inbox (destination chain) ---
    let inbox = Artifact::load(&contracts, "Inbox.sol/Inbox.json");
    inbox.assert_mirrored(
        "function",
        "deliverMessage(bytes32,address,bytes,bytes)",
        &IInbox::deliverMessageCall::SELECTOR,
    );
    inbox.assert_mirrored(
        "function",
        "retryPendingMessage(bytes32)",
        &IInbox::retryPendingMessageCall::SELECTOR,
    );
    inbox.assert_mirrored(
        "function",
        "isPending(bytes32)",
        &IInbox::isPendingCall::SELECTOR,
    );
    inbox.assert_mirrored(
        "event",
        IInbox::MessageDelivered::SIGNATURE,
        &IInbox::MessageDelivered::SIGNATURE_HASH.0,
    );
    inbox.assert_mirrored(
        "event",
        IInbox::MessagePending::SIGNATURE,
        &IInbox::MessagePending::SIGNATURE_HASH.0,
    );
    inbox.assert_mirrored(
        "error",
        "MessageAlreadyValidated()",
        &IInbox::MessageAlreadyValidated::SELECTOR,
    );

    // --- EOAValidator (destination chain) ---
    let validator = Artifact::load(&contracts, "EOAValidator.sol/EOAValidator.json");
    validator.assert_mirrored(
        "function",
        "attestors()",
        &IVoteValidator::attestorsCall::SELECTOR,
    );
    validator.assert_mirrored(
        "function",
        "threshold()",
        &IVoteValidator::thresholdCall::SELECTOR,
    );
    validator.assert_mirrored(
        "function",
        "attestorSetUpdateNonce()",
        &IVoteValidator::attestorSetUpdateNonceCall::SELECTOR,
    );
    validator.assert_mirrored(
        "function",
        "submitAttestorSetUpdate(address[],bytes)",
        &IVoteValidator::submitAttestorSetUpdateCall::SELECTOR,
    );

    // --- AcknowledgmentValidator (source chain; note the artifact DIR spells "Acknowledgement") ---
    let ackv = Artifact::load(
        &contracts,
        "AcknowledgementValidator.sol/AcknowledgmentValidator.json",
    );
    ackv.assert_mirrored(
        "function",
        "submitAcknowledgment(uint64,(uint8,bytes32,bytes),(bytes32,bytes32[]))",
        &IAcknowledgmentValidator::submitAcknowledgmentCall::SELECTOR,
    );
    ackv.assert_mirrored(
        "event",
        IAcknowledgmentValidator::Acknowledged::SIGNATURE,
        &IAcknowledgmentValidator::Acknowledged::SIGNATURE_HASH.0,
    );
    ackv.assert_mirrored(
        "event",
        IAcknowledgmentValidator::AckFeeClaimed::SIGNATURE,
        &IAcknowledgmentValidator::AckFeeClaimed::SIGNATURE_HASH.0,
    );
    ackv.assert_mirrored(
        "error",
        "NoMessageDeliveredLogs()",
        &IAcknowledgmentValidator::NoMessageDeliveredLogs::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "MalformedMessageDeliveredLog()",
        &IAcknowledgmentValidator::MalformedMessageDeliveredLog::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "EncodedTransactionTooLarge(uint256,uint256)",
        &IAcknowledgmentValidator::EncodedTransactionTooLarge::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "UnsupportedTxType(uint8)",
        &IAcknowledgmentValidator::UnsupportedTxType::SELECTOR,
    );
    ackv.assert_mirrored(
        "error",
        "OutboxNotSet()",
        &IAcknowledgmentValidator::OutboxNotSet::SELECTOR,
    );
    // ProofInvalid is declared by the USCProofVerifier the validator delegates to; the revert
    // bubbles through, so its selector is pinned against THAT artifact.
    let verifier = Artifact::load(
        &contracts,
        "common/USCProofVerifier.sol/USCProofVerifier.json",
    );
    verifier.assert_mirrored(
        "error",
        "ProofInvalid(bytes32,uint64)",
        &IAcknowledgmentValidator::ProofInvalid::SELECTOR,
    );

    // --- RelayerContract (source chain) ---
    let relayer = Artifact::load(&contracts, "RelayerContract.sol/RelayerContract.json");
    relayer.assert_mirrored(
        "function",
        "getMessageInfo(bytes32)",
        &IRelayerContract::getMessageInfoCall::SELECTOR,
    );
    relayer.assert_output_tuple(
        "getMessageInfo",
        "(address,uint32,uint256,uint256,uint256,uint256,uint256,bool,bool)",
    );
    relayer.assert_mirrored(
        "function",
        "claimDelivery(bytes32,bytes32,uint64,(uint8,bytes32,bytes),(bytes32,bytes32[]))",
        &IRelayerContract::claimDeliveryCall::SELECTOR,
    );
    relayer.assert_mirrored(
        "error",
        "UnknownOperation(bytes32)",
        &IRelayerContract::UnknownOperation::SELECTOR,
    );
    relayer.assert_mirrored(
        "error",
        "RelayAlreadySettled(bytes32)",
        &IRelayerContract::RelayAlreadySettled::SELECTOR,
    );
    relayer.assert_mirrored(
        "error",
        "NativeTransferFailed(address,uint256)",
        &IRelayerContract::NativeTransferFailed::SELECTOR,
    );

    // --- OutboxFactory (source chain) ---
    let factory = Artifact::load(&contracts, "deployer/OutboxFactory.sol/OutboxFactory.json");
    factory.assert_mirrored(
        "event",
        IOutboxFactory::OutboxCreated::SIGNATURE,
        &IOutboxFactory::OutboxCreated::SIGNATURE_HASH.0,
    );
}
