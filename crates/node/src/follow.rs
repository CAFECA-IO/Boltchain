//! Follower node: syncs blocks from IPFS announcements and serves JSON-RPC. With `--producer`
//! (single-producer devnet) it trusts that peer's announcements and forwards transactions to it;
//! without, it follows a public chain: mined blocks by their seals, PoS blocks by finality proofs.

use crate::{devnet::load_genesis, p2p::P2pArgs};
use alloy_primitives::B256;
use anyhow::Result;
use bolt_chain::Chain;
use bolt_net::NetHandle;
use bolt_rpc::{RpcContext, TxForwarder};
use bolt_sync::Follower;
use bolt_txpool::{PoolConfig, TxPool};
use libp2p::PeerId;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

/// Follower options.
#[derive(Debug, clap::Args)]
pub struct FollowArgs {
    /// Genesis file.
    #[arg(long, default_value = "genesis/dev.json")]
    pub genesis: PathBuf,
    /// Data directory.
    #[arg(long, default_value = "data/follower")]
    pub datadir: PathBuf,
    /// JSON-RPC listen address.
    #[arg(long, default_value = "127.0.0.1:8546")]
    pub rpc: SocketAddr,
    /// Peer id of the single block producer of a devnet; only its announcements are accepted.
    /// Omit it to follow a public chain.
    #[arg(long)]
    pub producer: Option<PeerId>,
    /// P2P options.
    #[command(flatten)]
    pub p2p: P2pArgs,
    /// Storage options (public chains only).
    #[command(flatten)]
    pub storage: crate::validator::StorageArgs,
    /// Serve Prometheus metrics and `/health` on this address.
    #[arg(long)]
    pub metrics: Option<SocketAddr>,
}

#[derive(Debug)]
struct Forward {
    net: NetHandle,
    producer: PeerId,
    rt: tokio::runtime::Handle,
}

impl TxForwarder for Forward {
    fn forward(&self, raw: Vec<u8>) -> Result<B256, String> {
        self.rt.block_on(self.net.forward_tx(self.producer, raw))
    }
}

/// Runs a follower until Ctrl-C.
pub async fn run(args: FollowArgs) -> Result<()> {
    let Some(producer) = args.producer else {
        return crate::validator::run(crate::validator::ValidatorArgs {
            genesis: args.genesis,
            datadir: args.datadir,
            key: vec![],
            rpc: args.rpc,
            block_time: None,
            timeout_ms: None,
            mining: crate::miner::MiningArgs {
                mine: false,
                beneficiary: None,
                mining_threads: 1,
                randomx_fast: false,
                extra_data: String::new(),
                gas_target: None,
            },
            p2p: args.p2p,
            storage: args.storage,
            metrics: args.metrics,
        })
        .await;
    };
    let genesis = load_genesis(&args.genesis)?;
    let chain = Arc::new(Chain::open(&args.datadir, &genesis)?);
    let cfg = chain.config().clone();
    let (net, events) = args.p2p.start(&args.datadir, chain.clone(), Some(producer)).await?;

    let ctx = RpcContext {
        chain: chain.clone(),
        pool: Arc::new(TxPool::new(PoolConfig::new(
            cfg.chain_id,
            cfg.gas_limit,
            cfg.min_base_fee_wei,
        ))),
        client_version: crate::CLIENT_VERSION.to_string(),
        host: None,
        relay: None,
        forwarder: Some(Arc::new(Forward {
            net: net.clone(),
            producer,
            rt: tokio::runtime::Handle::current(),
        })),
    };
    let (addr, handle) = bolt_rpc::start(args.rpc, ctx).await?;
    tracing::info!(%addr, head = chain.head()?.number, "follower JSON-RPC listening");

    let follower = tokio::spawn(bolt_sync::run_follower(Follower::new(chain, net), events));
    tokio::signal::ctrl_c().await?;
    follower.abort();
    handle.stop()?;
    Ok(())
}
