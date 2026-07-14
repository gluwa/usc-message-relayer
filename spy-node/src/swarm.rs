//! The spy's libp2p task: join the attestor mesh, observe, annotate, fan out.
//!
//! Reuses the relayer's [`RelayerBehavior`] (gossipsub Strict + `validate_messages`, kad,
//! identify, ping, mdns toggle, connection limits) and the shared `write-ability` topic ids, so
//! the spy is wire-identical to the relayer's observer half — one mesh, one stack.
//!
//! Gossipsub citizenship for a non-validator (spec §3): a decodable vote whose envelope
//! `chain_key` matches its topic is **Accept**ed and streamed — including votes whose signature
//! does *not* recover to the advertised signer. Signature validity is an **annotation**
//! (`signature_valid`), not a gate: the spy has no active-set view, the mesh's real validators
//! (attestors, relayer pool) enforce membership and reject forgeries themselves, and an observer
//! that Rejected on local crypto judgment would P4-penalize peers for traffic the validators may
//! accept. Only provably malformed frames (undecodable, topic/envelope mismatch) are Rejected.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::gossipsub::{IdentTopic, MessageAcceptance, TopicHash};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use message_relayer::health::Health;
use message_relayer::p2p::behavior::{RelayerBehavior, RelayerBehaviorEvent};
use message_relayer::p2p::{derive_keypair, protocols};
use write_ability::envelope::{MessageVote, ReobservationRequest};

use crate::config::P2pConfig;
use crate::events::SpyEvent;
use crate::hub::Hub;
use crate::metrics::{EventLabelKind, EventOutcome, SpyMetrics};

/// Backoff between listen retries (transient port conflicts from a restarting predecessor).
const LISTEN_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
/// Listen attempts before proceeding dial-only (loudly).
const LISTEN_RETRY_ATTEMPTS: u32 = 12;
/// Cadence of the swarm loop's liveness pulse into [`Health`]. A wedged loop stops pulsing and
/// `/health` flips 503 so orchestration restarts the spy.
const HEALTH_PULSE: std::time::Duration = std::time::Duration::from_secs(30);

/// A reobservation request a WS client asked the spy to gossip (spec §5, `allow_publish` only).
#[derive(Debug)]
pub struct PublishRequest {
    pub request: ReobservationRequest,
}

pub async fn run(
    p2p: P2pConfig,
    chain_keys: Vec<u64>,
    hub: Hub,
    mut publish_rx: mpsc::Receiver<PublishRequest>,
    metrics: Arc<SpyMetrics>,
    health: Arc<Health>,
    cancel: CancellationToken,
) -> Result<()> {
    let keypair =
        derive_keypair(p2p.identity.as_deref()).context("failed to derive libp2p identity")?;
    let local_peer_id = keypair.public().to_peer_id();
    info!(%local_peer_id, "🕵️ spy libp2p identity ready");

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| RelayerBehavior::new(key, !p2p.no_mdns))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    // Subscribe to the message-vote and reobservation topics per configured chain.
    let mut vote_topic_to_chain: HashMap<TopicHash, u64> = HashMap::new();
    let mut reobs_topic_to_chain: HashMap<TopicHash, u64> = HashMap::new();
    let mut chain_to_reobs_topic: HashMap<u64, IdentTopic> = HashMap::new();
    for ck in &chain_keys {
        let votes = IdentTopic::new(protocols::message_votes_topic(*ck));
        info!(chain_key = ck, topic = %votes, "📥 observing message votes");
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&votes)
            .with_context(|| format!("subscribe to {votes} failed"))?;
        vote_topic_to_chain.insert(votes.hash(), *ck);

        let reobs = IdentTopic::new(protocols::reobservation_topic(*ck));
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&reobs)
            .with_context(|| format!("subscribe to {reobs} failed"))?;
        reobs_topic_to_chain.insert(reobs.hash(), *ck);
        chain_to_reobs_topic.insert(*ck, reobs);
    }

    for boot in &p2p.boot_nodes {
        match boot.parse::<libp2p::Multiaddr>() {
            Ok(addr) => {
                if let Some(peer_id) = addr.iter().find_map(|p| match p {
                    libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
                    _ => None,
                }) {
                    info!(%addr, %peer_id, "👥 registering boot node");
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                } else {
                    warn!(%addr, "boot node address has no /p2p/ component; skipping");
                }
            }
            Err(err) => warn!(%boot, %err, "could not parse boot node multiaddr; skipping"),
        }
    }

    if let Some(public) = &p2p.public_addr {
        match format!("/dns4/{public}/tcp/{}", p2p.port).parse::<libp2p::Multiaddr>() {
            Ok(addr) => {
                info!(%addr, "📰 broadcasting external address");
                swarm.add_external_address(addr);
            }
            Err(err) => warn!(public, port = p2p.port, %err, "invalid public_addr"),
        }
    }

    // Only listen when a `public_addr` is configured. A listening spy leaks its discovered
    // listen addrs (loopback + cluster-local pod IP) to peers via identify, and the bootnode's
    // kad table then propagates that record mesh-wide: every attestor — including ones in other
    // clusters with no route to a pod IP — burns dial attempts on it until their unreachable-peer
    // eviction kicks in, and a restart (new pod IP, new ephemeral PeerId) leaves the stale record
    // behind to re-poison the mesh. A dial-only observer needs no inbound reachability at all:
    // gossipsub delivers over its outbound connections, and with no listen addrs identify has
    // nothing dialable to advertise.
    if p2p.public_addr.is_some() {
        // Retry the listen; after the budget proceed dial-only, loudly (mirrors the relayer).
        let listen: libp2p::Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p.port).parse()?;
        for attempt in 1..=LISTEN_RETRY_ATTEMPTS {
            match swarm.listen_on(listen.clone()) {
                Ok(_) => break,
                Err(err) if attempt == LISTEN_RETRY_ATTEMPTS => {
                    tracing::error!(
                        %listen, %err, attempts = attempt,
                        "swarm listen failed after retries — continuing DIAL-ONLY (inbound peers cannot reach this spy)"
                    );
                }
                Err(err) => {
                    warn!(%listen, %err, attempt, "swarm listen failed; retrying after backoff");
                    tokio::select! {
                        () = cancel.cancelled() => return Ok(()),
                        () = tokio::time::sleep(LISTEN_RETRY_BACKOFF) => {}
                    }
                }
            }
        }
    } else {
        info!("🕶️ no public_addr configured — dial-only observer; not listening, nothing dialable advertised");
    }

    info!(chains = chain_keys.len(), "✅ spy swarm online");

    let mut peer_counts: HashMap<u64, usize> = HashMap::new();
    let mut health_tick = tokio::time::interval(HEALTH_PULSE);
    health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    health.heartbeat("swarm");

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!("🛑 spy swarm exiting on cancel");
                return Ok(());
            }
            _ = health_tick.tick() => {
                health.heartbeat("swarm");
            }
            maybe = publish_rx.recv() => {
                let Some(PublishRequest { request }) = maybe else {
                    // WS layer holds the sender for the process lifetime; closure means shutdown.
                    debug!("publish channel closed");
                    continue;
                };
                let Some(topic) = chain_to_reobs_topic.get(&request.chain_key) else {
                    warn!(chain_key = request.chain_key, "publish for unobserved chain_key; dropping");
                    continue;
                };
                match swarm.behaviour_mut().gossipsub.publish(topic.hash(), request.encode_bytes()) {
                    Ok(_) => {
                        metrics.inc_reobservation_published();
                        debug!(chain_key = request.chain_key, "📣 gossiped reobservation request");
                    }
                    // No mesh peers is the common transient; the client retries on its own cadence.
                    Err(err) => debug!(chain_key = request.chain_key, %err, "reobservation publish failed"),
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &mut swarm,
                    &vote_topic_to_chain,
                    &reobs_topic_to_chain,
                    &hub,
                    metrics.as_ref(),
                    &mut peer_counts,
                );
            }
        }
    }
}

fn handle_swarm_event(
    event: libp2p::swarm::SwarmEvent<RelayerBehaviorEvent>,
    swarm: &mut libp2p::Swarm<RelayerBehavior>,
    vote_topic_to_chain: &HashMap<TopicHash, u64>,
    reobs_topic_to_chain: &HashMap<TopicHash, u64>,
    hub: &Hub,
    metrics: &SpyMetrics,
    peer_counts: &mut HashMap<u64, usize>,
) {
    match event {
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Identify(
            libp2p::identify::Event::Received {
                peer_id,
                info: libp2p::identify::Info { listen_addrs, .. },
                ..
            },
        )) => {
            for addr in listen_addrs {
                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
            }
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Mdns(
            libp2p::mdns::Event::Discovered(peers),
        )) => {
            for (peer_id, addr) in peers {
                debug!(%peer_id, %addr, "🛰️ mDNS discovered");
                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
            }
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Gossipsub(
            libp2p::gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            },
        )) => {
            let acceptance = if let Some(&chain_key) = vote_topic_to_chain.get(&message.topic) {
                observe_vote(chain_key, &message.data, &propagation_source, hub, metrics)
            } else if let Some(&chain_key) = reobs_topic_to_chain.get(&message.topic) {
                observe_reobservation(chain_key, &message.data, &propagation_source, hub, metrics)
            } else {
                trace!(topic = %message.topic, "message on unsubscribed topic");
                return;
            };
            swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &propagation_source, acceptance);
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Gossipsub(
            libp2p::gossipsub::Event::Subscribed { peer_id, topic },
        )) => {
            if let Some(&chain_key) = vote_topic_to_chain.get(&topic) {
                let entry = peer_counts.entry(chain_key).or_default();
                *entry += 1;
                metrics.set_subscribed_peers(chain_key, i64::try_from(*entry).unwrap_or(i64::MAX));
                hub.publish(SpyEvent::peer_status(chain_key, *entry));
            }
            trace!(%peer_id, %topic, "peer subscribed");
        }
        libp2p::swarm::SwarmEvent::Behaviour(RelayerBehaviorEvent::Gossipsub(
            libp2p::gossipsub::Event::Unsubscribed { peer_id, topic },
        )) => {
            if let Some(&chain_key) = vote_topic_to_chain.get(&topic) {
                let entry = peer_counts.entry(chain_key).or_default();
                *entry = entry.saturating_sub(1);
                metrics.set_subscribed_peers(chain_key, i64::try_from(*entry).unwrap_or(i64::MAX));
                hub.publish(SpyEvent::peer_status(chain_key, *entry));
            }
            trace!(%peer_id, %topic, "peer unsubscribed");
        }
        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "🔍 new listen address");
        }
        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            debug!(%peer_id, "🔗 connection established");
        }
        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
            debug!(%peer_id, "⛓️‍💥 connection closed");
        }
        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            debug!(?peer_id, %error, "outgoing connection error");
        }
        _ => {}
    }
}

/// Decode + annotate one message-vote frame. Returns the gossipsub acceptance (module docs).
fn observe_vote(
    chain_key: u64,
    data: &[u8],
    source: &libp2p::PeerId,
    hub: &Hub,
    metrics: &SpyMetrics,
) -> MessageAcceptance {
    let vote = match MessageVote::decode_bytes(data) {
        Ok(vote) if vote.chain_key == chain_key => vote,
        Ok(vote) => {
            warn!(
                %source,
                envelope_chain_key = vote.chain_key,
                topic_chain_key = chain_key,
                "vote envelope chain_key disagrees with topic — rejecting"
            );
            metrics.inc_event(EventLabelKind::MessageVote, EventOutcome::Rejected);
            return MessageAcceptance::Reject;
        }
        Err(err) => {
            warn!(%source, %err, "could not decode MessageVote — rejecting");
            metrics.inc_event(EventLabelKind::MessageVote, EventOutcome::Rejected);
            return MessageAcceptance::Reject;
        }
    };

    // Annotate, don't gate: recovery failure streams as `signature_valid: false` (module docs).
    let advertised = alloy::primitives::Address::from(vote.signer);
    let (signer, signature_valid) = match recover_signer(
        &alloy::primitives::B256::from(vote.message_hash),
        &vote.signature,
    ) {
        Ok(recovered) => (recovered, recovered == advertised),
        Err(_) => (advertised, false),
    };

    hub.publish(SpyEvent::message_vote(
        chain_key,
        vote.message_id,
        vote.message_hash,
        signer,
        signature_valid,
        &vote.signature,
        source,
    ));
    metrics.inc_event(EventLabelKind::MessageVote, EventOutcome::Accepted);
    MessageAcceptance::Accept
}

/// Decode one reobservation-request frame. Requests are unauthenticated by design (attestors
/// re-verify against their own RPC), so any decodable request is Accepted and streamed.
fn observe_reobservation(
    chain_key: u64,
    data: &[u8],
    source: &libp2p::PeerId,
    hub: &Hub,
    metrics: &SpyMetrics,
) -> MessageAcceptance {
    match ReobservationRequest::decode_bytes(data) {
        Ok(req) if req.chain_key == chain_key => {
            hub.publish(SpyEvent::reobservation_request(
                chain_key,
                req.message_id,
                req.tx_hash,
                req.block_height,
                source,
            ));
            metrics.inc_event(EventLabelKind::ReobservationRequest, EventOutcome::Accepted);
            MessageAcceptance::Accept
        }
        Ok(req) => {
            warn!(
                %source,
                envelope_chain_key = req.chain_key,
                topic_chain_key = chain_key,
                "reobservation envelope chain_key disagrees with topic — rejecting"
            );
            metrics.inc_event(EventLabelKind::ReobservationRequest, EventOutcome::Rejected);
            MessageAcceptance::Reject
        }
        Err(err) => {
            warn!(%source, %err, "could not decode ReobservationRequest — rejecting");
            metrics.inc_event(EventLabelKind::ReobservationRequest, EventOutcome::Rejected);
            MessageAcceptance::Reject
        }
    }
}

fn recover_signer(
    hash: &alloy::primitives::B256,
    raw: &[u8; 65],
) -> Result<alloy::primitives::Address> {
    let sig: alloy::primitives::Signature = raw[..]
        .try_into()
        .map_err(|e| anyhow::anyhow!("malformed signature bytes: {e}"))?;
    sig.recover_address_from_prehash(hash)
        .map_err(|e| anyhow::anyhow!("ecrecover failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sign a vote with a real key and run it through `observe_vote`: it must Accept, stream one
    /// event, and annotate `signature_valid: true` with the recovered signer.
    #[tokio::test]
    async fn observe_vote_streams_annotated_event() {
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;

        let signer = PrivateKeySigner::random();
        let hash = alloy::primitives::B256::repeat_byte(0xAB);
        let sig = signer.sign_hash_sync(&hash).unwrap();
        let mut raw = [0u8; 65];
        raw.copy_from_slice(&sig.as_bytes());

        let vote = MessageVote {
            chain_key: 102,
            message_id: [1u8; 32],
            message_hash: hash.0,
            signer: signer.address().into_array(),
            signature: raw,
        };

        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let metrics = SpyMetrics::new();
        let acceptance = observe_vote(
            102,
            &vote.encode_bytes(),
            &libp2p::PeerId::random(),
            &hub,
            &metrics,
        );
        assert!(matches!(acceptance, MessageAcceptance::Accept));

        let event = rx.recv().await.unwrap();
        let json = serde_json::to_value(&*event).unwrap();
        assert_eq!(json["type"], "message_vote");
        assert_eq!(json["signature_valid"], true);
        assert_eq!(
            json["signer"].as_str().unwrap().to_lowercase(),
            format!("{:?}", signer.address()).to_lowercase()
        );
    }

    /// A forged signer field must still stream (Accept) but be annotated invalid — the spy
    /// observes, the mesh's validators judge.
    #[tokio::test]
    async fn forged_signer_streams_with_signature_valid_false() {
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;

        let real = PrivateKeySigner::random();
        let hash = alloy::primitives::B256::repeat_byte(0xCD);
        let sig = real.sign_hash_sync(&hash).unwrap();
        let mut raw = [0u8; 65];
        raw.copy_from_slice(&sig.as_bytes());

        let impostor = alloy::primitives::Address::repeat_byte(0x66);
        let vote = MessageVote {
            chain_key: 102,
            message_id: [1u8; 32],
            message_hash: hash.0,
            signer: impostor.into_array(),
            signature: raw,
        };

        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let metrics = SpyMetrics::new();
        let acceptance = observe_vote(
            102,
            &vote.encode_bytes(),
            &libp2p::PeerId::random(),
            &hub,
            &metrics,
        );
        assert!(matches!(acceptance, MessageAcceptance::Accept));

        let json = serde_json::to_value(&*rx.recv().await.unwrap()).unwrap();
        assert_eq!(json["signature_valid"], false);
    }

    #[test]
    fn garbage_and_chain_mismatch_are_rejected() {
        let hub = Hub::new();
        let metrics = SpyMetrics::new();
        assert!(matches!(
            observe_vote(102, b"garbage", &libp2p::PeerId::random(), &hub, &metrics),
            MessageAcceptance::Reject
        ));

        let vote = MessageVote {
            chain_key: 7, // disagrees with topic chain 102
            message_id: [1u8; 32],
            message_hash: [2u8; 32],
            signer: [3u8; 20],
            signature: [0u8; 65],
        };
        assert!(matches!(
            observe_vote(
                102,
                &vote.encode_bytes(),
                &libp2p::PeerId::random(),
                &hub,
                &metrics
            ),
            MessageAcceptance::Reject
        ));
    }
}
