//! Single-producer development network: one node produces every block and announces it over
//! IPFS (gossipsub + Bitswap). Followers (`boltchain follow`) sync from those announcements.
//! M3 replaces the single producer with HotStuff-2.

use crate::p2p::P2pArgs;
use alloy_primitives::Address;
use anyhow::{Context, Result};
use bolt_chain::{BuiltBlock, Chain};
use bolt_net::NetEvent;
use bolt_primitives::Genesis;
use bolt_rpc::{HeadState, RpcContext};
use bolt_txpool::{PoolConfig, TxPool};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

/// Devnet options.
#[derive(Debug, clap::Args)]
pub struct DevnetArgs {
    /// Genesis file.
    #[arg(long, default_value = "genesis/dev.json")]
    pub genesis: PathBuf,
    /// Data directory.
    #[arg(long, default_value = "data/dev")]
    pub datadir: PathBuf,
    /// JSON-RPC listen address.
    #[arg(long, default_value = "127.0.0.1:8545")]
    pub rpc: SocketAddr,
    /// Fee recipient of produced blocks.
    #[arg(long, default_value_t = Address::ZERO)]
    pub coinbase: Address,
    /// Seconds between blocks (defaults to the genesis slot length).
    #[arg(long)]
    pub block_time: Option<u64>,
    /// Serve the block explorer (and the IPFS gateway) on this address, e.g. `127.0.0.1:8080`.
    #[arg(long, value_name = "ADDR")]
    pub explorer: Option<SocketAddr>,
    /// `Certificates` contract for the explorer's evidence certificates (ADR 0016).
    #[arg(long, value_name = "ADDRESS")]
    pub certificates: Option<Address>,
    /// CAFECA wallet the certificate page pays with.
    #[arg(long, default_value = "https://cafeca.io")]
    pub cafeca_wallet: String,
    /// Disable P2P (no announcements, no followers).
    #[arg(long)]
    pub no_p2p: bool,
    /// P2P options.
    #[command(flatten)]
    pub p2p: P2pArgs,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Loads and validates a genesis file.
pub fn load_genesis(path: &std::path::Path) -> Result<Genesis> {
    let json =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Genesis::from_json(&json)?)
}

/// Runs the devnet until Ctrl-C.
pub async fn run(args: DevnetArgs) -> Result<()> {
    let genesis = load_genesis(&args.genesis)?;
    let chain = Arc::new(Chain::open(&args.datadir, &genesis)?);
    let cfg = chain.config().clone();
    let pool =
        Arc::new(TxPool::new(PoolConfig::new(cfg.chain_id, cfg.gas_limit, cfg.min_base_fee_wei)));

    let ctx = RpcContext {
        chain: chain.clone(),
        pool: pool.clone(),
        client_version: crate::CLIENT_VERSION.to_string(),
        host: None,
        relay: None,
        forwarder: None,
    };
    let (addr, handle) = bolt_rpc::start(args.rpc, ctx).await?;
    tracing::info!(%addr, chain_id = cfg.chain_id, genesis = %chain.genesis_hash(), "JSON-RPC listening");

    if let Some(addr) = args.explorer {
        let certs = args.certificates.map(|a| {
            Arc::new(crate::certificates::Certs::new(
                a,
                args.cafeca_wallet.clone(),
                None,
                Some(args.datadir.join("cert-uploads.json")),
            ))
        });
        crate::explorer::spawn_address_index(chain.clone())?;
        let ex = crate::explorer::Explorer {
            chain: chain.clone(),
            pool: Some(pool.clone()),
            certs: certs.clone(),
            host: None,
        };
        crate::explorer::start(addr, ex).await?;
    }

    let net = if args.no_p2p {
        None
    } else {
        let (net, mut events) = args.p2p.start(&args.datadir, chain.clone(), None).await?;
        // Transactions forwarded by followers go into the local pool.
        let (chain2, pool2) = (chain.clone(), pool.clone());
        tokio::spawn(async move {
            while let Some(ev) = events.recv().await {
                if let NetEvent::Tx { raw, reply } = ev {
                    let (c, p) = (chain2.clone(), pool2.clone());
                    let res = tokio::task::spawn_blocking(move || {
                        let r = c.store().reader().map_err(|e| e.to_string())?;
                        p.add_raw(&raw, &HeadState(&r)).map_err(|e| e.to_string())
                    })
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));
                    let _ = reply.send(res);
                }
            }
        });
        Some(net)
    };

    let block_time = Duration::from_secs(args.block_time.unwrap_or(cfg.slot_seconds).max(1));
    let producer = {
        let chain = chain.clone();
        let pool = pool.clone();
        let coinbase = args.coinbase;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(block_time);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let (c, p) = (chain.clone(), pool.clone());
                match tokio::task::spawn_blocking(move || produce(&c, &p, coinbase)).await {
                    Ok(Ok(built)) => {
                        if let Some(net) = &net
                            && let Err(e) = bolt_sync::publish(net, &built).await
                        {
                            tracing::warn!("announce failed: {e}");
                        }
                    }
                    Ok(Err(e)) => tracing::error!("block production failed: {e:#}"),
                    Err(e) => tracing::error!("producer task panicked: {e}"),
                }
            }
        })
    };

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    producer.abort();
    handle.stop()?;
    Ok(())
}

/// Produces one block from the pool.
pub fn produce(chain: &Chain, pool: &TxPool, coinbase: Address) -> Result<BuiltBlock> {
    let base_fee = chain.next_base_fee()?;
    let candidates = {
        let r = chain.store().reader()?;
        pool.best(base_fee, &HeadState(&r))
    };
    let started = std::time::Instant::now();
    let built = chain.build_block(candidates, now(), coinbase)?;
    {
        let r = chain.store().reader()?;
        pool.on_new_block(&HeadState(&r));
        let invalid: Vec<_> = built.rejected.iter().filter(|r| r.2).map(|r| r.0).collect();
        pool.remove(&invalid);
    }
    tracing::info!(
        number = built.header.number,
        hash = %built.hash,
        root = %built.bundle.root,
        txs = built.included.len(),
        rejected = built.rejected.len(),
        gas = built.header.gas_used,
        ms = started.elapsed().as_millis() as u64,
        "produced block"
    );
    for (h, why, _) in &built.rejected {
        tracing::debug!(tx = %h, reason = %why, "rejected");
    }
    Ok(built)
}
