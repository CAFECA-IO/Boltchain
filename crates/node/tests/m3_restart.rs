//! A validator that joins mid-epoch (restarted, or new) proposes at once (testnet observation,
//! 2026-09-27): it has missed the latest proposal, so every later proposal builds on a block it
//! does not have. Before the orphan cache it rejected them all — and could not propose in its own
//! rounds — until the next epoch, costing a round timeout each time it led.

use bolt_chain::Chain;
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_primitives::{Genesis, bls::dev_key};
use bolt_sync::ChainBlocks;
use boltchain::validator::{Validator, ValidatorConfig};
use libp2p::{Multiaddr, identity};
use std::{path::Path, sync::Arc, time::Duration};

fn genesis() -> Genesis {
    Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap()
}

async fn start_net(
    chain: Arc<Chain>,
    boot: Vec<Multiaddr>,
) -> (NetHandle, tokio::sync::mpsc::Receiver<NetEvent>) {
    bolt_net::start(
        NetConfig {
            chain_id: chain.config().chain_id,
            keypair: identity::Keypair::generate_ed25519(),
            listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            bootnodes: boot,
            producer: None,
            fork_id: chain.fork_id().unwrap().to_string(),
            fork_check: None,
            relay_server: false,
            agent: String::new(),
        },
        Arc::new(ChainBlocks(chain)),
    )
    .await
    .unwrap()
}

async fn addr_of(net: &NetHandle) -> Multiaddr {
    loop {
        if let Some(a) = net.listen_addrs().await.into_iter().next() {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct Node {
    chain: Arc<Chain>,
    net: NetHandle,
    task: tokio::task::JoinHandle<()>,
}

async fn start(dir: &Path, i: u32, boot: Vec<Multiaddr>) -> Node {
    let chain = Arc::new(Chain::open(dir, &genesis()).unwrap());
    let cfg = chain.config().clone();
    let (net, events) = start_net(chain.clone(), boot).await;
    let pool = Arc::new(bolt_txpool::TxPool::new(bolt_txpool::PoolConfig::new(
        cfg.chain_id,
        cfg.gas_limit,
        cfg.min_base_fee_wei,
    )));
    let v = Validator {
        chain: chain.clone(),
        pool,
        net: net.clone(),
        keys: vec![dev_key(i)],
        cfg: ValidatorConfig {
            slot_ms: 1000,
            base_timeout_ms: 2500,
            state_dir: dir.join("consensus"),
        },
        miner: None,
    };
    let task = tokio::spawn(async move {
        if let Err(e) = v.run(events).await {
            eprintln!("validator {i}: {e:#}");
        }
    });
    Node { chain, net, task }
}

fn height(n: &Node) -> u64 {
    n.chain.head().unwrap().number
}

async fn wait_for(n: &Node, h: u64, secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while height(n) < h {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for height {h}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn late_validator_keeps_its_slots() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,libmdbx=off".into()),
        )
        .with_test_writer()
        .try_init();
    // Validator 6 starts late (as after a restart, or a new machine): it has missed the latest
    // proposals when it joins mid-epoch.
    let dirs: Vec<_> = (0..7).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut nodes = Vec::new();
    let mut boot = Vec::new();
    for (i, d) in dirs.iter().enumerate().take(6) {
        let n = start(d.path(), i as u32, boot.clone()).await;
        if boot.len() < 2 {
            boot.push(addr_of(&n.net).await);
        }
        nodes.push(n);
    }
    wait_for(&nodes[0], 8, 120).await;
    nodes.push(start(dirs[6].path(), 6, boot.clone()).await);

    // Let it rejoin, then every slot must be filled: a missed round costs a 2.5 s timeout.
    let from = height(&nodes[0]) + 4;
    wait_for(&nodes[0], from + 28, 120).await;
    let times: Vec<u64> = {
        let r = nodes[0].chain.store().reader().unwrap();
        (from..=from + 28).map(|h| r.header(h).unwrap().unwrap().timestamp).collect()
    };
    let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    eprintln!("block gaps after validator 6 joined: {gaps:?}");
    assert!(
        gaps.iter().all(|g| *g <= 2),
        "a round timed out after validator 6 joined (gaps {gaps:?})"
    );
    wait_for(&nodes[6], from + 28, 30).await;

    for n in nodes {
        n.task.abort();
        n.net.shutdown().await;
    }
}

/// Every validator stops at once (testnet, 2026-10-01: both hosts rebooted) and restarts on its
/// data. The highest certificate names a block that was certified but not yet final, which every
/// node held only in memory: before pending blocks were recorded, each leader failed with "parent
/// block not available" and the chain never moved again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whole_committee_restarts() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,libmdbx=off".into()),
        )
        .with_test_writer()
        .try_init();
    // Each node runs on its own runtime; shutting that down ends all its tasks at once, like the
    // process dying.
    struct Proc {
        rt: tokio::runtime::Runtime,
        node: Node,
    }
    let boot_all = async |dirs: &[tempfile::TempDir]| {
        let mut procs = Vec::new();
        let mut boot = Vec::new();
        for (i, d) in dirs.iter().enumerate() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let (path, b) = (d.path().to_path_buf(), boot.clone());
            let node = rt.spawn(async move { start(&path, i as u32, b).await }).await.unwrap();
            if boot.len() < 2 {
                boot.push(addr_of(&node.net).await);
            }
            procs.push(Proc { rt, node });
        }
        procs
    };
    let kill_all = async |procs: Vec<Proc>| {
        let mut weak = Vec::new();
        for p in procs {
            weak.push(Arc::downgrade(&p.node.chain));
            drop(p.node);
            p.rt.shutdown_background();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while weak.iter().any(|w| w.strong_count() > 0) {
            assert!(tokio::time::Instant::now() < deadline, "database still open after the kill");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let head = |p: &Proc| height(&p.node);
    let wait = async |p: &Proc, h: u64, secs: u64| wait_for(&p.node, h, secs).await;

    let dirs: Vec<_> = (0..7).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut procs = boot_all(&dirs).await;
    wait(&procs[0], 6, 90).await;
    for round in 0..3 {
        let at = head(&procs[0]);
        eprintln!("kill {round}: all validators at height {at}");
        kill_all(procs).await;
        procs = boot_all(&dirs).await;
        wait(&procs[0], at + 6, 90).await;
    }
    kill_all(procs).await;
}
