//! Shared HTTP client for the proof-gen API server's `proof-by-tx` endpoint, used by every
//! proof submitter (ack, claim).
//!
//! `GET {base}/api/v1/proof-by-tx/{chain_key}/{tx_hash}` returns the prover `txBytes` (encoded
//! tx + receipt) plus the merkle-inclusion and continuity proofs for the block containing the
//! transaction. HTTP 422 means the block is not yet attested (`BlockNotReady`) — the normal early
//! state of every request, mapped to [`ProofFetch::NotReady`] so callers defer instead of erroring.

use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Bytes, B256};
use anyhow::{Context, Result};
use serde::Deserialize;

use crate::abi::{ContinuityProof, MerkleProof, MerkleProofEntry};

/// Minimal HTTP client for the proof-gen API server's `proof-by-tx` endpoint.
pub struct ProofGenClient {
    http: reqwest::Client,
    base: String,
}

pub enum ProofFetch {
    Ready(SingleContinuityResponse),
    /// HTTP 422 — the block containing the tx is not yet attested.
    NotReady,
}

impl ProofGenClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build proof-gen HTTP client")?;
        Ok(Self {
            http,
            base: base_url.trim_end_matches('/').to_string(),
        })
    }

    pub async fn proof_by_tx(&self, chain_key: u64, tx_hash: B256) -> Result<ProofFetch> {
        let url = format!(
            "{}/api/v1/proof-by-tx/{}/{:#x}",
            self.base, chain_key, tx_hash
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url} failed"))?;

        // 422 (BlockNotReady) is expected while the destination block is still being attested.
        if resp.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Ok(ProofFetch::NotReady);
        }
        let status = resp.status();
        let body = resp
            .text()
            .await
            .with_context(|| format!("reading body of {url}"))?;
        if !status.is_success() {
            anyhow::bail!("proof-gen returned {status} for {url}: {body}");
        }
        let parsed: SingleContinuityResponse = serde_json::from_str(&body)
            .with_context(|| format!("decoding proof-gen response from {url}"))?;
        Ok(ProofFetch::Ready(parsed))
    }
}

// ---------------------------------------------------------------------------
// proof-gen response shape (mirrors proof-gen-api-server SingleContinuityResponse)
// ---------------------------------------------------------------------------

/// Subset of the proof-gen `SingleContinuityResponse` the submitters need. Field names are
/// camelCase to match the server's `#[serde(rename_all = "camelCase")]`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleContinuityResponse {
    pub header_number: u64,
    /// Hex-encoded prover `txBytes` (encoded tx + receipt). `None` when the server only returned a
    /// continuity proof (no merkle inclusion) — which would not satisfy any proof consumer.
    tx_bytes: Option<String>,
    continuity_proof: ContinuityProofJson,
    merkle_proof: MerkleProofJson,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinuityProofJson {
    lower_endpoint_digest: String,
    roots: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MerkleProofJson {
    root: String,
    siblings: Vec<MerkleProofEntryJson>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MerkleProofEntryJson {
    hash: String,
    is_left: bool,
}

impl SingleContinuityResponse {
    /// Hex-decode the prover `txBytes` into the calldata the on-chain verifier expects.
    pub fn encoded_transaction(&self) -> Result<Bytes> {
        let raw = self.tx_bytes.as_deref().context(
            "proof-gen response missing txBytes (continuity-only proof cannot be submitted)",
        )?;
        let bytes =
            hex::decode(raw.trim_start_matches("0x")).context("txBytes is not valid hex")?;
        Ok(Bytes::from(bytes))
    }

    /// Convert the JSON proof bundle into the `sol!`-generated argument structs.
    pub fn to_proofs(&self) -> Result<(MerkleProof, ContinuityProof)> {
        let merkle = MerkleProof {
            root: parse_b256(&self.merkle_proof.root).context("merkle_proof.root")?,
            siblings: self
                .merkle_proof
                .siblings
                .iter()
                .map(|s| {
                    Ok(MerkleProofEntry {
                        hash: parse_b256(&s.hash).context("merkle_proof.siblings[].hash")?,
                        isLeft: s.is_left,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };

        let continuity = ContinuityProof {
            lowerEndpointDigest: parse_b256(&self.continuity_proof.lower_endpoint_digest)
                .context("continuity_proof.lower_endpoint_digest")?,
            roots: self
                .continuity_proof
                .roots
                .iter()
                .map(|r| parse_b256(r).context("continuity_proof.roots[]"))
                .collect::<Result<Vec<_>>>()?,
        };

        Ok((merkle, continuity))
    }
}

fn parse_b256(s: &str) -> Result<B256> {
    B256::from_str(s.trim()).with_context(|| format!("not a 32-byte hex value: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "headerNumber": 42,
        "txBytes": "0xdeadbeef",
        "continuityProof": {
            "lowerEndpointDigest": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "roots": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
        },
        "merkleProof": {
            "root": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "siblings": [
                { "hash": "0x4444444444444444444444444444444444444444444444444444444444444444", "isLeft": true }
            ]
        }
    }"#;

    #[test]
    fn parses_proof_gen_response_and_builds_sol_structs() {
        let parsed: SingleContinuityResponse = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(parsed.header_number, 42);
        assert_eq!(
            parsed.encoded_transaction().unwrap().as_ref(),
            [0xde, 0xad, 0xbe, 0xef]
        );
        let (merkle, continuity) = parsed.to_proofs().unwrap();
        assert_eq!(merkle.siblings.len(), 1);
        assert!(merkle.siblings[0].isLeft);
        assert_eq!(continuity.roots.len(), 1);
    }

    #[test]
    fn missing_tx_bytes_is_an_error() {
        let json = SAMPLE.replace("\"txBytes\": \"0xdeadbeef\",", "");
        let parsed: SingleContinuityResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.encoded_transaction().is_err());
    }
}
