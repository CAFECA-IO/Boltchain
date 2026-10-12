//! Boltchain networking on libp2p.
//!
//! * Transports: QUIC (preferred) and TCP + Noise + Yamux, with DNS (including `/dnsaddr`).
//! * Discovery: Kademlia on the chain's own protocol id (`/bolt/<chain id>/kad/1.0.0`), so the
//!   Boltchain swarm stays separate from the public IPFS DHT.
//! * Announcements: gossipsub topic `/bolt/<chain id>/announce`, signed by the author.
//! * Block exchange: Bitswap 1.2.0 (see [`bitswap`]).
//! * Transaction forwarding: request-response `/bolt/<chain id>/tx/1.0.0` to the block producer.
//! * NAT traversal: AutoNAT (am I reachable?), UPnP port mapping, circuit relay v2 (public nodes
//!   with `relay_server` relay for others; a node found to be behind NAT reserves a slot on up to
//!   two relay-capable peers and is reachable through them) and DCUtR hole punching, which
//!   upgrades relayed connections to direct ones when the NATs allow it.

pub mod bitswap;

use alloy_primitives::B256;
use bitswap::{Bitswap, BlockSource, FetchError};
use bolt_ipld::Cid;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, autonat, dcutr, gossipsub, identify, identity, kad,
    multiaddr::Protocol,
    noise, ping, relay, request_response,
    swarm::{NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle},
    tcp, upnp, yamux,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

/// Default P2P port (TCP and UDP/QUIC).
pub const DEFAULT_PORT: u16 = 8017;

/// Maximum gossip message (announcements may inline up to 64 KiB of body).
pub const MAX_GOSSIP_BYTES: usize = 512 * 1024;

/// Mainnet bootstrap nodes. Each name publishes `_dnsaddr` TXT records with its current
/// addresses and peer id, so hosts can move without a client release.
pub fn mainnet_bootnodes() -> Vec<Multiaddr> {
    (1..=9)
        .map(|i| format!("/dnsaddr/node{i:03}.cafeca.io").parse().expect("valid multiaddr"))
        .collect()
}

/// Default listen addresses on `port`.
pub fn default_listen(port: u16) -> Vec<Multiaddr> {
    vec![
        format!("/ip4/0.0.0.0/udp/{port}/quic-v1").parse().expect("valid multiaddr"),
        format!("/ip4/0.0.0.0/tcp/{port}").parse().expect("valid multiaddr"),
    ]
}

/// A body chunk carried inside an announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineBlock {
    /// CID.
    pub cid: Cid,
    /// Content.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// New-block announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announce {
    /// Block number.
    pub height: u64,
    /// Envelope CID.
    pub root: Cid,
    /// Envelope bytes (small; saves one round trip).
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    /// Header RLP (about 600 bytes).
    #[serde(with = "serde_bytes")]
    pub header: Vec<u8>,
    /// Body chunks, when the body is small enough to inline.
    pub inline: Vec<InlineBlock>,
    /// Finality proof (consensus networks): encoded `CommitProof` for this block.
    #[serde(default, with = "serde_bytes")]
    pub proof: Vec<u8>,
    /// Sender's clock (unix ms) at publication, set by the network task: a re-announcement of
    /// the same block is then a new gossip message (gossipsub drops repeats of recent messages
    /// by content), so peers that joined since still receive it.
    #[serde(default)]
    pub at: u64,
}

impl Announce {
    /// Encodes as dag-cbor.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("announce serializes")
    }

    /// Decodes dag-cbor.
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(b).ok()
    }
}

/// Transaction forwarding request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRequest(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Transaction forwarding response: the hash, or the pool's rejection reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResponse(pub Result<B256, String>);

/// Network configuration.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Chain id (namespaces every protocol).
    pub chain_id: u64,
    /// Node identity.
    pub keypair: identity::Keypair,
    /// Listen addresses.
    pub listen: Vec<Multiaddr>,
    /// Peers to dial at start (with or without `/p2p/<id>`; `/dnsaddr` supported).
    pub bootnodes: Vec<Multiaddr>,
    /// Only announcements authored by this peer are accepted and relayed (single-producer
    /// devnet). `None` accepts announcements from anyone (validation moves to consensus in M3).
    pub producer: Option<PeerId>,
    /// This node's fork id (ADR 0008 §2), advertised in the identify agent string.
    pub fork_id: String,
    /// Judges a peer's fork id; peers on incompatible rules are disconnected.
    pub fork_check: Option<ForkCheck>,
    /// Relay connections for peers behind NAT (public nodes).
    pub relay_server: bool,
}

/// Verdict on a peer's fork id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRules {
    /// Same rules.
    Compatible,
    /// The peer runs software with a fork this node does not know: the operator should upgrade.
    Newer,
    /// Different rules.
    Incompatible,
}

/// Fork id checker: peer fork id string -> verdict.
#[derive(Clone)]
pub struct ForkCheck(pub std::sync::Arc<dyn Fn(&str) -> PeerRules + Send + Sync>);

impl std::fmt::Debug for ForkCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ForkCheck")
    }
}

/// Events delivered to the node.
#[derive(Debug)]
pub enum NetEvent {
    /// A valid-looking announcement arrived.
    Announce {
        /// Peer that relayed it to us (best first source for its blocks).
        via: PeerId,
        /// The announcement.
        announce: Announce,
    },
    /// A peer forwarded a transaction; answer through `reply`.
    Tx {
        /// Raw EIP-2718 bytes.
        raw: Vec<u8>,
        /// Reply channel.
        reply: oneshot::Sender<Result<B256, String>>,
    },
    /// A consensus message (proposal, vote or timeout), still encoded.
    Consensus {
        /// Peer that relayed it.
        via: PeerId,
        /// dag-cbor bytes.
        data: Vec<u8>,
    },
    /// A transaction gossiped by a peer (raw EIP-2718 bytes, not yet validated).
    GossipTx {
        /// Raw transaction.
        raw: Vec<u8>,
    },
    /// A storage-layer message (snapshot announcement or audit vote), still encoded.
    Storage {
        /// Peer that relayed it.
        via: PeerId,
        /// Encoded message.
        data: Vec<u8>,
    },
    /// A connection was established.
    Connected(PeerId),
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    stream: libp2p_stream::Behaviour,
    tx: request_response::cbor::Behaviour<TxRequest, TxResponse>,
    autonat: autonat::Behaviour,
    upnp: upnp::tokio::Behaviour,
    relay_client: relay::client::Behaviour,
    relay: Toggle<relay::Behaviour>,
    dcutr: dcutr::Behaviour,
}

/// Circuit relay v2 hop protocol (a peer that relays for others).
const RELAY_HOP: &str = "/libp2p/circuit/relay/0.2.0/hop";

/// Relays a node behind NAT reserves slots on.
const MAX_RELAYS: usize = 2;

enum Command {
    Publish(Announce),
    PublishConsensus(Vec<u8>),
    PublishStorage(Vec<u8>),
    PublishTx(Vec<u8>),
    ForwardTx(PeerId, Vec<u8>, oneshot::Sender<Result<B256, String>>),
    RespondTx(u64, Result<B256, String>),
    Peers(oneshot::Sender<Vec<PeerId>>),
    ListenAddrs(oneshot::Sender<Vec<Multiaddr>>),
    Dial(Multiaddr),
    Listen(Multiaddr),
    Shutdown,
}

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Transport or behaviour setup failed.
    #[error("setup: {0}")]
    Setup(String),
    /// The network task stopped.
    #[error("network task stopped")]
    Stopped,
    /// Blocks did not arrive in time.
    #[error(transparent)]
    Fetch(#[from] FetchError),
}

/// Handle to the running network.
#[derive(Clone, Debug)]
pub struct NetHandle {
    cmd: mpsc::Sender<Command>,
    bitswap: Bitswap,
    peer_id: PeerId,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Command::Publish(_) => "Publish",
            Command::PublishConsensus(_) => "PublishConsensus",
            Command::PublishStorage(_) => "PublishStorage",
            Command::PublishTx(_) => "PublishTx",
            Command::ForwardTx(..) => "ForwardTx",
            Command::RespondTx(..) => "RespondTx",
            Command::Peers(_) => "Peers",
            Command::ListenAddrs(_) => "ListenAddrs",
            Command::Dial(_) => "Dial",
            Command::Listen(_) => "Listen",
            Command::Shutdown => "Shutdown",
        })
    }
}

impl NetHandle {
    /// This node's peer id.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Publishes an announcement.
    pub async fn publish(&self, a: Announce) -> Result<(), NetError> {
        self.cmd.send(Command::Publish(a)).await.map_err(|_| NetError::Stopped)
    }

    /// Publishes an encoded consensus message.
    pub async fn publish_consensus(&self, data: Vec<u8>) -> Result<(), NetError> {
        self.cmd.send(Command::PublishConsensus(data)).await.map_err(|_| NetError::Stopped)
    }

    /// Publishes an encoded storage-layer message (ADR 0009).
    pub async fn publish_storage(&self, data: Vec<u8>) -> Result<(), NetError> {
        self.cmd.send(Command::PublishStorage(data)).await.map_err(|_| NetError::Stopped)
    }

    /// Gossips a transaction this node admitted (never blocks: dropped if the network task is
    /// saturated, like any gossip).
    pub fn gossip_tx(&self, raw: Vec<u8>) {
        let _ = self.cmd.try_send(Command::PublishTx(raw));
    }

    /// Asks `peer` alone for one block, bypassing the local blockstore (storage audits).
    pub async fn probe(
        &self,
        cid: Cid,
        peer: PeerId,
        timeout: Duration,
    ) -> Result<Vec<u8>, NetError> {
        Ok(self.bitswap.probe(cid, peer, timeout).await?)
    }

    /// Fetches blocks over bitswap: `peers[0]` first, the others on its DONT_HAVE or after
    /// 150 ms, repeating every 150 ms for up to 5 s.
    pub async fn fetch(
        &self,
        cids: &[Cid],
        peers: &[PeerId],
    ) -> Result<HashMap<Cid, Vec<u8>>, NetError> {
        Ok(self
            .bitswap
            .fetch(cids, peers, Duration::from_millis(150), Duration::from_secs(5))
            .await?)
    }

    /// Forwards a raw transaction to `peer` (the producer) and returns its answer.
    pub async fn forward_tx(&self, peer: PeerId, raw: Vec<u8>) -> Result<B256, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Command::ForwardTx(peer, raw, tx))
            .await
            .map_err(|_| "network stopped".to_string())?;
        rx.await.map_err(|_| "network stopped".to_string())?
    }

    /// Currently connected peers.
    pub async fn peers(&self) -> Vec<PeerId> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Peers(tx)).await.is_err() {
            return vec![];
        }
        rx.await.unwrap_or_default()
    }

    /// Addresses we listen on (with `/p2p/<id>` appended).
    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::ListenAddrs(tx)).await.is_err() {
            return vec![];
        }
        rx.await.unwrap_or_default()
    }

    /// Stops the network (closes all connections).
    pub async fn shutdown(&self) {
        let _ = self.cmd.send(Command::Shutdown).await;
    }

    /// Dials an address.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), NetError> {
        self.cmd.send(Command::Dial(addr)).await.map_err(|_| NetError::Stopped)
    }

    /// Listens on an additional address, e.g. `<relay>/p2p/<id>/p2p-circuit` to be reachable
    /// through a relay.
    pub async fn listen(&self, addr: Multiaddr) -> Result<(), NetError> {
        self.cmd.send(Command::Listen(addr)).await.map_err(|_| NetError::Stopped)
    }
}

fn topic(chain_id: u64) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(format!("/bolt/{chain_id}/announce"))
}

fn consensus_topic(chain_id: u64) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(format!("/bolt/{chain_id}/consensus"))
}

fn tx_topic(chain_id: u64) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(format!("/bolt/{chain_id}/tx"))
}

fn storage_topic(chain_id: u64) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(format!("/bolt/{chain_id}/storage"))
}

/// Behind NAT: listen through relay-capable peers (up to [`MAX_RELAYS`]).
fn listen_via_relays(
    swarm: &mut Swarm<Behaviour>,
    candidates: &HashMap<PeerId, Multiaddr>,
    relayed: &mut std::collections::HashSet<PeerId>,
) {
    for (peer, addr) in candidates {
        if relayed.len() >= MAX_RELAYS {
            break;
        }
        if relayed.contains(peer) {
            continue;
        }
        let circuit = addr.clone().with(Protocol::P2pCircuit);
        match swarm.listen_on(circuit.clone()) {
            Ok(_) => {
                tracing::info!(relay = %peer, "behind NAT: listening through relay");
                relayed.insert(*peer);
            }
            Err(e) => tracing::debug!(%circuit, "relay listen failed: {e}"),
        }
    }
}

/// Who can use an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Globally routable (or a DNS name).
    Public,
    /// RFC 1918, CGNAT, unique-local IPv6.
    Private,
    /// Loopback.
    Loopback,
    /// Unspecified, link-local, multicast, documentation, container bridges.
    Unroutable,
}

fn addr_scope(addr: &Multiaddr) -> Scope {
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => {
                let o = ip.octets();
                return if ip.is_loopback() {
                    Scope::Loopback
                } else if ip.is_unspecified()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || (o[0] == 172 && o[1] == 17)
                {
                    // 172.17/16 is Docker's default bridge: never reachable from another host.
                    Scope::Unroutable
                } else if ip.is_private() || (o[0] == 100 && (64..128).contains(&o[1])) {
                    Scope::Private
                } else {
                    Scope::Public
                };
            }
            Protocol::Ip6(ip) => {
                let s = ip.segments();
                return if ip.is_loopback() {
                    Scope::Loopback
                } else if ip.is_unspecified() || ip.is_multicast() || (s[0] & 0xffc0) == 0xfe80 {
                    Scope::Unroutable
                } else if (s[0] & 0xfe00) == 0xfc00 {
                    Scope::Private
                } else {
                    Scope::Public
                };
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                return Scope::Public;
            }
            _ => {}
        }
    }
    Scope::Unroutable
}

fn peer_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| if let Protocol::P2p(id) = p { Some(id) } else { None })
}

/// Starts the network.
pub async fn start(
    cfg: NetConfig,
    source: Arc<dyn BlockSource>,
) -> Result<(NetHandle, mpsc::Receiver<NetEvent>), NetError> {
    let setup = |e: &dyn std::fmt::Display| NetError::Setup(e.to_string());
    let chain_id = cfg.chain_id;
    let fork_id = cfg.fork_id.clone();
    let relay_server = cfg.relay_server;
    let kad_protocol = StreamProtocol::try_from_owned(format!("/bolt/{chain_id}/kad/1.0.0"))
        .map_err(|e| setup(&e))?;
    let tx_protocol = StreamProtocol::try_from_owned(format!("/bolt/{chain_id}/tx/1.0.0"))
        .map_err(|e| setup(&e))?;

    let mut swarm: Swarm<Behaviour> =
        libp2p::SwarmBuilder::with_existing_identity(cfg.keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| setup(&e))?
            .with_quic()
            .with_dns()
            .map_err(|e| setup(&e))?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| setup(&e))?
            .with_behaviour(|key, relay_client| {
                let peer_id = key.public().to_peer_id();
                let gossip_cfg = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(700))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .validate_messages()
                    .max_transmit_size(MAX_GOSSIP_BYTES)
                    .message_id_fn(|m: &gossipsub::Message| {
                        gossipsub::MessageId::from(alloy_primitives::keccak256(&m.data).to_vec())
                    })
                    .build()
                    .map_err(|e| e.to_string())?;
                let mut gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossip_cfg,
                )?;
                let (params, thresholds) = score_params(chain_id);
                gossipsub.with_peer_score(params, thresholds)?;
                let mut kad_cfg = kad::Config::new(kad_protocol.clone());
                kad_cfg.set_query_timeout(Duration::from_secs(30));
                let mut kad = kad::Behaviour::with_config(
                    peer_id,
                    kad::store::MemoryStore::new(peer_id),
                    kad_cfg,
                );
                kad.set_mode(Some(kad::Mode::Server));
                Ok(Behaviour {
                    identify: identify::Behaviour::new(
                        identify::Config::new(format!("/bolt/{chain_id}/1.0.0"), key.public())
                            .with_agent_version(format!(
                                "boltchain/{} fork/{}",
                                env!("CARGO_PKG_VERSION"),
                                fork_id
                            )),
                    ),
                    ping: ping::Behaviour::default(),
                    kad,
                    gossipsub,
                    stream: libp2p_stream::Behaviour::new(),
                    tx: request_response::cbor::Behaviour::new(
                        [(tx_protocol, request_response::ProtocolSupport::Full)],
                        request_response::Config::default()
                            .with_request_timeout(Duration::from_secs(10)),
                    ),
                    autonat: autonat::Behaviour::new(
                        peer_id,
                        autonat::Config {
                            boot_delay: Duration::from_secs(10),
                            retry_interval: Duration::from_secs(60),
                            refresh_interval: Duration::from_secs(15 * 60),
                            only_global_ips: false,
                            ..Default::default()
                        },
                    ),
                    upnp: upnp::tokio::Behaviour::default(),
                    relay_client,
                    relay: Toggle::from(relay_server.then(|| {
                        relay::Behaviour::new(
                            peer_id,
                            relay::Config {
                                max_reservations: 256,
                                max_circuits: 256,
                                // Relayed peers sync blocks through us until hole punching gives
                                // them a direct path: allow more than the libp2p defaults (2 min,
                                // 128 KiB per circuit).
                                max_circuit_duration: Duration::from_secs(30 * 60),
                                max_circuit_bytes: 256 << 20,
                                ..Default::default()
                            },
                        )
                    })),
                    dcutr: dcutr::Behaviour::new(peer_id),
                })
            })
            .map_err(|e| setup(&e))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

    for addr in &cfg.listen {
        swarm.listen_on(addr.clone()).map_err(|e| setup(&e))?;
    }
    swarm.behaviour_mut().gossipsub.subscribe(&topic(chain_id)).map_err(|e| setup(&e))?;
    swarm.behaviour_mut().gossipsub.subscribe(&consensus_topic(chain_id)).map_err(|e| setup(&e))?;
    swarm.behaviour_mut().gossipsub.subscribe(&storage_topic(chain_id)).map_err(|e| setup(&e))?;
    swarm.behaviour_mut().gossipsub.subscribe(&tx_topic(chain_id)).map_err(|e| setup(&e))?;
    for addr in &cfg.bootnodes {
        if let Some(peer) = peer_of(addr) {
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
        }
        if let Err(e) = swarm.dial(addr.clone()) {
            tracing::warn!(%addr, "dial bootnode: {e}");
        }
    }

    let bitswap = Bitswap::new(swarm.behaviour().stream.new_control(), source);
    let peer_id = *swarm.local_peer_id();
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (ev_tx, ev_rx) = mpsc::channel(EVENT_BUFFER);
    tokio::spawn(run(swarm, cfg, kad_protocol, cmd_rx, cmd_tx.clone(), ev_tx));
    Ok((NetHandle { cmd: cmd_tx, bitswap, peer_id }, ev_rx))
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    cfg: NetConfig,
    kad_protocol: StreamProtocol,
    mut cmd_rx: mpsc::Receiver<Command>,
    cmd_tx: mpsc::Sender<Command>,
    ev_tx: mpsc::Sender<NetEvent>,
) {
    let topic = topic(cfg.chain_id);
    let ctopic = consensus_topic(cfg.chain_id);
    let stopic = storage_topic(cfg.chain_id);
    let ttopic = tx_topic(cfg.chain_id);
    let mut pending_fwd: HashMap<
        request_response::OutboundRequestId,
        oneshot::Sender<Result<B256, String>>,
    > = HashMap::new();
    let mut inbound_tx: HashMap<u64, request_response::ResponseChannel<TxResponse>> =
        HashMap::new();
    let mut next_id = 0u64;
    // How we reached each peer (scope of the remote address of our connection).
    let mut reach: HashMap<PeerId, Scope> = HashMap::new();
    let mut last_at = 0u64;
    let mut published = RecentlyPublished::default();
    let mut storage_rate: HashMap<PeerId, (u32, std::time::Instant)> = HashMap::new();
    // NAT traversal: relay-capable peers (dialable address with /p2p) and the ones we listen via.
    let mut relay_candidates: HashMap<PeerId, Multiaddr> = HashMap::new();
    let mut relayed: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
    let mut behind_nat = false;
    let mut bootstrap_tick = tokio::time::interval(Duration::from_secs(60));
    // Chain peers (identify passed the fork check) and when their first connection opened.
    let mut chain_peers: HashMap<PeerId, std::time::Instant> = HashMap::new();
    let mut subs_tick = tokio::time::interval(Duration::from_secs(10));
    let mut last_publish_warn: Option<std::time::Instant> = None;
    // Peers dropped for missing subscriptions, redialled once their last connection closed (a
    // dial while an old connection is still open would again be a "second" connection).
    let mut redial: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
    // Open connections per peer. Extra ones (AutoNAT dial-backs, simultaneous dials, a hole punch
    // next to its relayed connection) are closed after a grace period: they would otherwise stay
    // open for good (the testnet ran out of file descriptors after a week, 2026-10-11).
    let mut conns: HashMap<PeerId, HashMap<libp2p::swarm::ConnectionId, ConnInfo>> = HashMap::new();

    loop {
        tokio::select! {
            _ = subs_tick.tick() => {
                // Gossipsub sends its subscriptions only on a peer's first connection. When a
                // peer restarts while we still hold a stale connection to its old process, its
                // new connection counts as a second one: it never learns our topics (and we may
                // never learn its), so it cannot publish to us — the one-sided meshes behind the
                // testnet finality stalls. A chain peer that announced no topics well after
                // connecting is dropped and redialled, which exchanges subscriptions afresh.
                let now = std::time::Instant::now();
                let silent = stale_subscriptions(
                    swarm.behaviour().gossipsub.all_peers().map(|(p, t)| (*p, t.len())),
                    &chain_peers,
                    now,
                );
                for peer in silent {
                    tracing::warn!(%peer, "peer announced no gossip subscriptions; reconnecting");
                    chain_peers.remove(&peer);
                    redial.insert(peer);
                    let _ = swarm.disconnect_peer_id(peer);
                }
                for (peer, cs) in &conns {
                    for id in redundant(cs, now) {
                        tracing::debug!(%peer, ?id, "closing a redundant connection");
                        swarm.close_connection(id);
                    }
                }
            }
            _ = bootstrap_tick.tick() => {
                let _ = swarm.behaviour_mut().kad.bootstrap();
                // Gossip health: peers whose score keeps them out of the mesh stop relaying.
                let g = &swarm.behaviour().gossipsub;
                let mesh = g.mesh_peers(&ctopic.hash()).count();
                let scores: Vec<String> = g
                    .all_peers()
                    .filter_map(|(p, _)| g.peer_score(p).map(|s| format!("{}:{s:.1}", short_peer(p))))
                    .collect();
                tracing::info!(consensus_mesh = mesh, scores = %scores.join(" "), "gossip");
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Command::Publish(mut a) => {
                        // Unique per message even when two go out in the same millisecond.
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        last_at = now.max(last_at + 1);
                        a.at = last_at;
                        let data = a.encode();
                        // Validators on one host commit the same block in the same millisecond
                        // and so build byte-identical announcements; when a peer's copy arrived
                        // first ours is already out (gossipsub would refuse it with a warning).
                        if !published.fresh(&data) {
                            tracing::trace!(height = a.height, "announcement already gossiped");
                            continue;
                        }
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                            tracing::debug!(height = a.height, "publish announce: {e}");
                        }
                    }
                    Command::PublishConsensus(data) => {
                        if !published.fresh(&data) {
                            continue;
                        }
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(ctopic.clone(), data) {
                            // A validator that cannot publish stalls its rounds: say so (at most
                            // every 30 s) rather than only at debug level.
                            let now = std::time::Instant::now();
                            if last_publish_warn.is_none_or(|t| now.duration_since(t) > Duration::from_secs(30)) {
                                last_publish_warn = Some(now);
                                tracing::warn!("publish consensus message failed: {e}");
                            } else {
                                tracing::debug!("publish consensus: {e}");
                            }
                        }
                    }
                    Command::PublishTx(raw) => {
                        if !published.fresh(&raw) {
                            continue;
                        }
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(ttopic.clone(), raw) {
                            tracing::debug!("publish tx: {e}");
                        }
                    }
                    Command::PublishStorage(data) => {
                        if !published.fresh(&data) {
                            continue;
                        }
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(stopic.clone(), data) {
                            tracing::debug!("publish storage: {e}");
                        }
                    }
                    Command::ForwardTx(peer, raw, reply) => {
                        let id = swarm.behaviour_mut().tx.send_request(&peer, TxRequest(raw));
                        pending_fwd.insert(id, reply);
                    }
                    Command::RespondTx(id, res) => {
                        if let Some(ch) = inbound_tx.remove(&id) {
                            let _ = swarm.behaviour_mut().tx.send_response(ch, TxResponse(res));
                        }
                    }
                    Command::Peers(reply) => {
                        let _ = reply.send(swarm.connected_peers().copied().collect());
                    }
                    Command::ListenAddrs(reply) => {
                        let me = *swarm.local_peer_id();
                        let _ = reply.send(swarm.listeners().map(|a| a.clone().with(Protocol::P2p(me))).collect());
                    }
                    Command::Shutdown => break,
                    Command::Dial(addr) => {
                        if let Some(peer) = peer_of(&addr) {
                            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
                        }
                        let _ = swarm.dial(addr);
                    }
                    Command::Listen(addr) => {
                        if let Err(e) = swarm.listen_on(addr.clone()) {
                            tracing::warn!(%addr, "listen: {e}");
                        }
                    }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!(%address, "p2p listening");
                    // A relay only offers its service once it knows an address others can
                    // reach it at: a relay server's own listen addresses are that.
                    if cfg.relay_server
                        && matches!(addr_scope(&address), Scope::Public | Scope::Loopback)
                        && !address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                    {
                        swarm.add_external_address(address);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established, .. } => {
                    if let Some(cs) = conns.get_mut(&peer_id) {
                        cs.remove(&connection_id);
                        if cs.is_empty() {
                            conns.remove(&peer_id);
                        }
                    }
                    if num_established > 0 {
                        continue;
                    }
                    reach.remove(&peer_id);
                    chain_peers.remove(&peer_id);
                    if redial.remove(&peer_id) {
                        let _ = swarm.dial(peer_id);
                    }
                    storage_rate.remove(&peer_id);
                    relay_candidates.remove(&peer_id);
                }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, num_established, endpoint, .. } => {
                    let relayed = endpoint.get_remote_address().iter().any(|p| matches!(p, Protocol::P2pCircuit));
                    conns.entry(peer_id).or_default().insert(
                        connection_id,
                        ConnInfo { relayed, opened: std::time::Instant::now(), last_pong: None },
                    );
                    reach.insert(peer_id, addr_scope(endpoint.get_remote_address()));
                    if num_established.get() == 1 {
                        deliver(&ev_tx, NetEvent::Connected(peer_id));
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    let remote = info.agent_version.split_whitespace().find_map(|t| t.strip_prefix("fork/"));
                    let verdict = match (&cfg.fork_check, remote) {
                        (None, _) => PeerRules::Compatible,
                        (Some(check), Some(r)) => (check.0)(r),
                        // Not a Boltchain node (e.g. a stock IPFS client fetching blocks over
                        // Bitswap): keep the connection, but it is not a chain peer.
                        (Some(_), None) => {
                            tracing::debug!(%peer_id, agent = %info.agent_version, "non-Boltchain peer (IPFS client)");
                            continue;
                        }
                    };
                    match verdict {
                        PeerRules::Incompatible => {
                            tracing::debug!(%peer_id, agent = %info.agent_version, "peer runs incompatible rules; disconnecting");
                            swarm.behaviour_mut().kad.remove_peer(&peer_id);
                            let _ = swarm.disconnect_peer_id(peer_id);
                            continue;
                        }
                        PeerRules::Newer => tracing::warn!(
                            %peer_id,
                            agent = %info.agent_version,
                            "a peer announces a hard fork this software does not know: upgrade the node"
                        ),
                        PeerRules::Compatible => {}
                    }
                    chain_peers.entry(peer_id).or_insert_with(std::time::Instant::now);
                    if info.protocols.iter().any(|p| p.as_ref() == RELAY_HOP)
                        && let Some(a) = info.listen_addrs.iter().find(|a| {
                            addr_scope(a) == Scope::Public
                                && !a.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                        })
                    {
                        let a = if peer_of(a).is_some() { a.clone() } else { a.clone().with(Protocol::P2p(peer_id)) };
                        relay_candidates.insert(peer_id, a);
                        if behind_nat {
                            listen_via_relays(&mut swarm, &relay_candidates, &mut relayed);
                        }
                    }
                    if info.protocols.contains(&kad_protocol) {
                        // Only addresses others can use: public ones, plus private or loopback
                        // ones when we reach this peer that way ourselves (LAN, local tests).
                        // Otherwise nodes behind NAT or in containers would spread 192.168.x /
                        // 172.17.x addresses that nobody else can dial.
                        let via = reach.get(&peer_id).copied().unwrap_or(Scope::Public);
                        for addr in info.listen_addrs {
                            match addr_scope(&addr) {
                                Scope::Public => {}
                                Scope::Unroutable => continue,
                                s if s == via => {}
                                _ => continue,
                            }
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source, message_id, message,
                })) if message.topic == ctopic.hash() => {
                    // Signatures are checked by the consensus engine; relay promptly.
                    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                        &message_id, &propagation_source, gossipsub::MessageAcceptance::Accept,
                    );
                    bolt_primitives::metrics::CONSENSUS_MSGS.inc();
                    bolt_primitives::metrics::CONSENSUS_BYTES.add(message.data.len() as u64);
                    deliver(&ev_tx, NetEvent::Consensus { via: propagation_source, data: message.data });
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source, message_id, message,
                })) if message.topic == ttopic.hash() => {
                    // Stateless checks here (a peer relaying a malformed or wrongly signed
                    // transaction is penalised by peer scoring); nonce and balance in the pool.
                    let ok = tx_stateless_ok(&message.data, cfg.chain_id);
                    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                        &message_id, &propagation_source,
                        if ok { gossipsub::MessageAcceptance::Accept } else { gossipsub::MessageAcceptance::Reject },
                    );
                    if ok {
                        deliver(&ev_tx, NetEvent::GossipTx { raw: message.data });
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source, message_id, message,
                })) if message.topic == stopic.hash() => {
                    // Checked by the node (signatures, snapshot roots against local headers);
                    // each peer may relay a bounded number per minute.
                    let now = std::time::Instant::now();
                    let (count, since) = storage_rate.entry(propagation_source).or_insert((0, now));
                    if now.duration_since(*since) > Duration::from_secs(60) {
                        (*count, *since) = (0, now);
                    }
                    *count += 1;
                    let within = *count <= MAX_STORAGE_PER_MINUTE && message.data.len() <= 64 * 1024;
                    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                        &message_id, &propagation_source,
                        if within { gossipsub::MessageAcceptance::Accept } else { gossipsub::MessageAcceptance::Ignore },
                    );
                    if within {
                        deliver(&ev_tx, NetEvent::Storage { via: propagation_source, data: message.data });
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source, message_id, message,
                })) => {
                    let author = message.source;
                    let allowed = match cfg.producer {
                        Some(p) => author == Some(p),
                        None => true,
                    };
                    published.seen(&message.data);
                    let decoded = if allowed { Announce::decode(&message.data) } else { None };
                    let acceptance = if decoded.is_some() {
                        gossipsub::MessageAcceptance::Accept
                    } else {
                        gossipsub::MessageAcceptance::Reject
                    };
                    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                        &message_id, &propagation_source, acceptance,
                    );
                    if let Some(announce) = decoded {
                        deliver(&ev_tx, NetEvent::Announce { via: propagation_source, announce });
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Tx(request_response::Event::Message { message, .. })) => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let id = next_id;
                        next_id += 1;
                        inbound_tx.insert(id, channel);
                        let (reply, rx) = oneshot::channel();
                        // If the node is saturated the reply is dropped and the peer gets an error.
                        deliver(&ev_tx, NetEvent::Tx { raw: request.0, reply });
                        let cmd_tx = cmd_tx.clone();
                        tokio::spawn(async move {
                            let res = rx.await.unwrap_or_else(|_| Err("node dropped the request".into()));
                            let _ = cmd_tx.send(Command::RespondTx(id, res)).await;
                        });
                    }
                    request_response::Message::Response { request_id, response } => {
                        if let Some(reply) = pending_fwd.remove(&request_id) {
                            let _ = reply.send(response.0);
                        }
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new })) => {
                    tracing::info!(?old, ?new, "NAT status");
                    behind_nat = matches!(new, autonat::NatStatus::Private);
                    if behind_nat {
                        listen_via_relays(&mut swarm, &relay_candidates, &mut relayed);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Upnp(e)) => match e {
                    upnp::Event::NewExternalAddr { external_addr, .. } => tracing::info!(address = %external_addr, "UPnP port mapping added"),
                    upnp::Event::NonRoutableGateway => tracing::debug!("UPnP gateway is not routable"),
                    upnp::Event::GatewayNotFound => tracing::debug!("no UPnP gateway"),
                    upnp::Event::ExpiredExternalAddr { external_addr, .. } => tracing::debug!(address = %external_addr, "UPnP mapping expired"),
                },
                SwarmEvent::Behaviour(BehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted { relay_peer_id, .. })) => {
                    tracing::info!(relay = %relay_peer_id, "reachable through relay");
                }
                SwarmEvent::Behaviour(BehaviourEvent::Dcutr(e)) => match e.result {
                    Ok(_) => tracing::info!(peer = %e.remote_peer_id, "hole punch succeeded: direct connection"),
                    Err(err) => tracing::debug!(peer = %e.remote_peer_id, "hole punch failed: {err}"),
                },
                SwarmEvent::ExternalAddrConfirmed { address } => tracing::info!(%address, "external address confirmed"),
                SwarmEvent::ListenerClosed { addresses, .. } => {
                    // A relay went away: forget it so another can be used.
                    for a in &addresses {
                        if a.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                            && let Some(p) = peer_of(a)
                        {
                            relayed.remove(&p);
                        }
                    }
                    if behind_nat {
                        listen_via_relays(&mut swarm, &relay_candidates, &mut relayed);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Tx(request_response::Event::OutboundFailure { request_id, error, .. })) => {
                    if let Some(reply) = pending_fwd.remove(&request_id) {
                        let _ = reply.send(Err(format!("forwarding failed: {error}")));
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { peer, connection, result: Ok(_) })) => {
                    if let Some(c) = conns.get_mut(&peer).and_then(|cs| cs.get_mut(&connection)) {
                        c.last_pong = Some(std::time::Instant::now());
                    }
                }
                _ => {}
            }
        }
    }
}

/// Storage-topic messages (snapshot announcements, audit votes) relayed per peer per minute.
const MAX_STORAGE_PER_MINUTE: u32 = 600;

/// Whether gossiped bytes are a well-formed, correctly signed transaction for this chain.
fn tx_stateless_ok(raw: &[u8], chain_id: u64) -> bool {
    use alloy_consensus::{Transaction as _, TxEnvelope, transaction::SignerRecoverable};
    use alloy_eips::eip2718::Decodable2718;
    if raw.is_empty() || raw.len() > MAX_TX_GOSSIP_BYTES {
        return false;
    }
    let mut buf = raw;
    let Ok(tx) = TxEnvelope::decode_2718(&mut buf) else { return false };
    buf.is_empty()
        && !tx.is_eip4844()
        && tx.chain_id() == Some(chain_id)
        && tx.recover_signer().is_ok()
}

/// How long a chain peer may stay connected without announcing any gossip topic.
const SUBSCRIPTION_GRACE: Duration = Duration::from_secs(20);

/// One open connection to a peer.
#[derive(Debug, Clone, Copy)]
struct ConnInfo {
    /// Through a circuit relay.
    relayed: bool,
    /// When it was established.
    opened: std::time::Instant,
    /// Last successful ping on it.
    last_pong: Option<std::time::Instant>,
}

/// How long an extra connection may stay open (an AutoNAT dial-back or a hole punch completes
/// well within it).
const EXTRA_CONNECTION_GRACE: Duration = Duration::from_secs(30);

/// A connection without a successful ping for this long is not trusted to be alive (pings go
/// every 15 s).
const PING_STALE: Duration = Duration::from_secs(45);

/// Connections to one peer that should be closed: all but the best one, once past
/// [`EXTRA_CONNECTION_GRACE`]. Best: direct before relayed, then answering pings (a connection
/// to a peer's previous, dead process does not), then the oldest (gossipsub and Bitswap streams
/// already run on it).
fn redundant(
    cs: &HashMap<libp2p::swarm::ConnectionId, ConnInfo>,
    now: std::time::Instant,
) -> Vec<libp2p::swarm::ConnectionId> {
    if cs.len() < 2 {
        return Vec::new();
    }
    let alive = |c: &ConnInfo| {
        c.last_pong.map_or(now.duration_since(c.opened) < PING_STALE, |t| {
            now.duration_since(t) < PING_STALE
        })
    };
    let Some(keep) =
        cs.iter().min_by_key(|(id, c)| (c.relayed, !alive(c), c.opened, **id)).map(|(id, _)| *id)
    else {
        return Vec::new();
    };
    cs.iter()
        .filter(|(id, c)| **id != keep && now.duration_since(c.opened) >= EXTRA_CONNECTION_GRACE)
        .map(|(id, _)| *id)
        .collect()
}

/// Chain peers connected longer than [`SUBSCRIPTION_GRACE`] whose gossip subscriptions we never
/// received (`gossip` lists each gossipsub peer with its number of topics; chain peers missing
/// from it have not even opened gossipsub).
fn stale_subscriptions(
    gossip: impl Iterator<Item = (PeerId, usize)>,
    chain_peers: &HashMap<PeerId, std::time::Instant>,
    now: std::time::Instant,
) -> Vec<PeerId> {
    let topics: HashMap<PeerId, usize> = gossip.collect();
    let mut out: Vec<PeerId> = chain_peers
        .iter()
        .filter(|(_, since)| now.duration_since(**since) > SUBSCRIPTION_GRACE)
        .filter(|(p, _)| topics.get(p).copied().unwrap_or(0) == 0)
        .map(|(p, _)| *p)
        .collect();
    out.sort();
    out
}

fn short_peer(p: &PeerId) -> String {
    let s = p.to_string();
    s[s.len().saturating_sub(6)..].to_owned()
}

/// Messages this node published recently. Gossipsub refuses (and logs a warning for) a message
/// identical to one it saw within its duplicate-cache window, so repeats (re-broadcast votes,
/// timeouts, storage messages) are dropped here quietly; after the window a repeat goes out again.
#[derive(Default)]
struct RecentlyPublished {
    seen: HashMap<B256, std::time::Instant>,
}

impl RecentlyPublished {
    /// Gossipsub's default duplicate-cache time.
    const WINDOW: Duration = Duration::from_secs(60);

    /// Records `data` as received from the network (publishing it again would be a duplicate).
    fn seen(&mut self, data: &[u8]) {
        self.seen.insert(alloy_primitives::keccak256(data), std::time::Instant::now());
    }

    /// Whether `data` was neither published nor received within the window (and records it).
    fn fresh(&mut self, data: &[u8]) -> bool {
        let now = std::time::Instant::now();
        if self.seen.len() > 4096 {
            self.seen.retain(|_, t| now.duration_since(*t) < Self::WINDOW);
        }
        let id = alloy_primitives::keccak256(data);
        match self.seen.get(&id) {
            Some(t) if now.duration_since(*t) < Self::WINDOW => false,
            _ => {
                self.seen.insert(id, now);
                true
            }
        }
    }
}

/// Peer scoring (gossipsub v1.1): peers that relay invalid messages (undecodable announcements,
/// malformed or wrongly signed transactions) lose score and are eventually ignored. Delivery-rate
/// penalties are off: our topics are quiet (a block every few seconds, few transactions), and
/// several honest nodes may share an address (containers, one operator's host), so co-location
/// is not penalised either.
fn score_params(chain_id: u64) -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    let topic = |weight: f64| gossipsub::TopicScoreParams {
        topic_weight: weight,
        time_in_mesh_weight: 0.01,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 3600.0,
        first_message_deliveries_weight: 1.0,
        first_message_deliveries_decay: 0.9,
        first_message_deliveries_cap: 100.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: -100.0,
        invalid_message_deliveries_decay: 0.5,
        ..Default::default()
    };
    let mut params =
        gossipsub::PeerScoreParams { ip_colocation_factor_weight: 0.0, ..Default::default() };
    for (name, weight) in [("announce", 1.0), ("consensus", 1.0), ("tx", 0.5), ("storage", 0.5)] {
        let t = gossipsub::IdentTopic::new(format!("/bolt/{chain_id}/{name}"));
        params.topics.insert(t.hash(), topic(weight));
    }
    let thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -500.0,
        publish_threshold: -1000.0,
        graylist_threshold: -2500.0,
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    };
    (params, thresholds)
}

/// Largest transaction relayed by gossip (the pool's own limit is 128 KiB).
const MAX_TX_GOSSIP_BYTES: usize = 128 * 1024;

/// Events buffered between the network task and the node.
const EVENT_BUFFER: usize = 1024;

/// Hands an event to the node without ever blocking the swarm: a node that falls behind loses
/// gossip (which is lossy anyway, and recovered through announcements and certificates) instead
/// of stalling Bitswap and every other protocol for all its peers.
fn deliver(tx: &mpsc::Sender<NetEvent>, ev: NetEvent) {
    if let Err(mpsc::error::TrySendError::Full(ev)) = tx.try_send(ev) {
        bolt_primitives::metrics::EVENTS_DROPPED.inc();
        tracing::warn!(event = ev.kind(), "node is not keeping up; dropped a network event");
    }
}

impl NetEvent {
    fn kind(&self) -> &'static str {
        match self {
            NetEvent::Announce { .. } => "announce",
            NetEvent::Tx { .. } => "tx",
            NetEvent::Consensus { .. } => "consensus",
            NetEvent::Storage { .. } => "storage",
            NetEvent::GossipTx { .. } => "tx gossip",
            NetEvent::Connected(_) => "connected",
        }
    }
}

/// Loads an ed25519 node key from `path`, creating it on first use.
pub fn load_or_create_key(path: &std::path::Path) -> std::io::Result<identity::Keypair> {
    if let Ok(bytes) = std::fs::read(path) {
        return identity::Keypair::from_protobuf_encoding(&bytes).map_err(std::io::Error::other);
    }
    let key = identity::Keypair::generate_ed25519();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let bytes = key.to_protobuf_encoding().map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)?;
    Ok(key)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn chain_peers_without_subscriptions_are_reconnected_after_a_grace_period() {
        let now = std::time::Instant::now();
        let (a, b, c, d) = (PeerId::random(), PeerId::random(), PeerId::random(), PeerId::random());
        let old = now - SUBSCRIPTION_GRACE - Duration::from_secs(1);
        let chain: HashMap<PeerId, std::time::Instant> =
            [(a, old), (b, old), (c, now), (d, old)].into_iter().collect();
        // a: subscribed; b: known to gossipsub without topics; c: too recent; d: absent.
        let gossip = [(a, 4usize), (b, 0), (c, 0)].into_iter();
        let mut want = vec![b, d];
        want.sort();
        assert_eq!(stale_subscriptions(gossip, &chain, now), want);
        // An IPFS client (not a chain peer) without topics is left alone.
        let ipfs = PeerId::random();
        assert!(stale_subscriptions([(ipfs, 0)].into_iter(), &HashMap::new(), now).is_empty());
    }

    #[test]
    fn one_connection_per_peer_is_kept() {
        use libp2p::swarm::ConnectionId;
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let c = |relayed, opened, pong: Option<u64>| ConnInfo {
            relayed,
            opened: at(opened),
            last_pong: pong.map(at),
        };
        let (a, b, r) = (
            ConnectionId::new_unchecked(1),
            ConnectionId::new_unchecked(2),
            ConnectionId::new_unchecked(3),
        );
        // An AutoNAT dial-back next to a live connection: closed after the grace period only.
        let mut cs = HashMap::from([(a, c(false, 0, Some(100))), (b, c(false, 100, Some(110)))]);
        assert!(redundant(&cs, at(110)).is_empty(), "still in its grace period");
        assert_eq!(redundant(&cs, at(131)), vec![b], "the newer one goes");
        // The old connection went to the peer's previous process (no pong for a while): keep
        // the new one.
        cs.insert(a, c(false, 0, Some(60)));
        assert_eq!(redundant(&cs, at(131)), vec![a]);
        // A hole punch replaces the relayed connection even though it is newer.
        let cs = HashMap::from([(r, c(true, 0, Some(100))), (b, c(false, 90, Some(100)))]);
        assert_eq!(redundant(&cs, at(125)), vec![r]);
        // A single connection is never touched, healthy or not.
        assert!(redundant(&HashMap::from([(a, c(true, 0, None))]), at(1000)).is_empty());
    }

    #[test]
    fn repeats_are_not_republished_within_the_window() {
        let mut r = RecentlyPublished::default();
        assert!(r.fresh(b"vote"));
        assert!(!r.fresh(b"vote"));
        assert!(r.fresh(b"other"));
        let id = alloy_primitives::keccak256(b"vote");
        r.seen.insert(id, std::time::Instant::now() - RecentlyPublished::WINDOW);
        assert!(r.fresh(b"vote"), "goes out again after the window");
        r.seen(b"announce from a peer");
        assert!(!r.fresh(b"announce from a peer"), "a copy received first is not published");
    }

    #[test]
    fn address_scopes() {
        let sc = |a: &str| addr_scope(&a.parse().unwrap());
        assert_eq!(sc("/ip4/211.22.118.149/tcp/8017"), Scope::Public);
        assert_eq!(sc("/ip4/192.168.50.40/udp/8017/quic-v1"), Scope::Private);
        assert_eq!(sc("/ip4/172.17.0.1/tcp/8017"), Scope::Unroutable);
        assert_eq!(sc("/ip4/127.0.0.1/tcp/8017"), Scope::Loopback);
        assert_eq!(sc("/ip4/100.64.1.2/tcp/1"), Scope::Private);
        assert_eq!(sc("/dns4/node001.cafeca.io/tcp/8017"), Scope::Public);
        assert_eq!(sc("/ip6/fe80::1/tcp/1"), Scope::Unroutable);
        assert_eq!(sc("/ip6/2001:4860::8888/tcp/1"), Scope::Public);
    }

    #[test]
    fn score_params_are_valid_and_txs_checked() {
        let (p, t) = score_params(1337);
        assert!(p.validate().is_ok() && t.validate().is_ok());
        assert!(!tx_stateless_ok(&[], 1337));
        assert!(!tx_stateless_ok(&[0x02, 0xc0], 1337));
    }
}
