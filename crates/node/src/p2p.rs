//! P2P options shared by the devnet producer and followers.

use anyhow::{Context, Result};
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_sync::ChainBlocks;
use libp2p::{Multiaddr, PeerId};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::mpsc;

/// P2P options.
#[derive(Debug, Clone, clap::Args)]
pub struct P2pArgs {
    /// P2P port (QUIC/UDP and TCP).
    #[arg(long, default_value_t = bolt_net::DEFAULT_PORT)]
    pub p2p_port: u16,
    /// Listen address for P2P (defaults to all interfaces).
    #[arg(long, default_value = "0.0.0.0")]
    pub p2p_host: String,
    /// Node identity key (ed25519, created if missing). Defaults to `<datadir>/node.key`.
    #[arg(long)]
    pub node_key: Option<PathBuf>,
    /// Peers to connect to at start, e.g. `/ip4/1.2.3.4/udp/8017/quic-v1/p2p/12D3...`.
    #[arg(long)]
    pub bootnode: Vec<Multiaddr>,
    /// Use the built-in mainnet bootstrap nodes (node001–node009.cafeca.io).
    #[arg(long)]
    pub mainnet_bootnodes: bool,
    /// Relay connections for peers behind NAT (circuit relay v2). For nodes with a public
    /// address; nodes behind NAT find relays and use them automatically.
    #[arg(long)]
    pub relay_server: bool,
}

impl P2pArgs {
    /// Starts the network for `chain`.
    pub async fn start(
        &self,
        datadir: &Path,
        chain: Arc<bolt_chain::Chain>,
        producer: Option<PeerId>,
    ) -> Result<(NetHandle, mpsc::Receiver<NetEvent>)> {
        let key_path = self.node_key.clone().unwrap_or_else(|| datadir.join("node.key"));
        let keypair = bolt_net::load_or_create_key(&key_path)
            .with_context(|| format!("node key {}", key_path.display()))?;
        let listen = vec![
            format!("/ip4/{}/udp/{}/quic-v1", self.p2p_host, self.p2p_port).parse()?,
            format!("/ip4/{}/tcp/{}", self.p2p_host, self.p2p_port).parse()?,
        ];
        let mut bootnodes = self.bootnode.clone();
        if self.mainnet_bootnodes {
            bootnodes.extend(bolt_net::mainnet_bootnodes());
        }
        let fork_id = chain.fork_id()?;
        let checker = chain.clone();
        let fork_check = bolt_net::ForkCheck(Arc::new(move |remote: &str| {
            use bolt_primitives::forks::{Compatibility, ForkId, check, forks};
            let Ok(remote) = remote.parse::<ForkId>() else {
                return bolt_net::PeerRules::Incompatible;
            };
            let head = checker.head().map(|h| h.number).unwrap_or(0);
            match check(&checker.genesis_hash(), forks(checker.config().chain_id), head, &remote) {
                Compatibility::Compatible => bolt_net::PeerRules::Compatible,
                Compatibility::PeerKnowsNewerFork => bolt_net::PeerRules::Newer,
                Compatibility::Incompatible => bolt_net::PeerRules::Incompatible,
            }
        }));
        let cfg = NetConfig {
            chain_id: chain.config().chain_id,
            keypair,
            listen,
            bootnodes,
            producer,
            fork_id: fork_id.to_string(),
            fork_check: Some(fork_check),
            relay_server: self.relay_server,
            agent: crate::CLIENT_VERSION.to_string(),
        };
        let (net, events) = bolt_net::start(cfg, Arc::new(ChainBlocks(chain))).await?;
        tracing::info!(peer_id = %net.peer_id(), "p2p identity");
        Ok((net, events))
    }
}
