//! M3 acceptance: seven validators (staked in the dev genesis) reach consensus over libp2p on
//! localhost.
//! Two of them are stopped; the remaining five (> 2/3) keep finalizing blocks. A follower that is
//! not a validator accepts blocks only with a valid finality proof and ends on the same head.

use bolt_chain::Chain;
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_primitives::{Genesis, bls::dev_key};
use bolt_sync::{ChainBlocks, Follower};
use boltchain::validator::{Finality, Validator, ValidatorConfig};
use libp2p::{Multiaddr, identity};
use std::{sync::Arc, time::Duration};

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
    _dir: tempfile::TempDir,
}

fn head(n: &Node) -> (u64, alloy_primitives::B256) {
    let h = n.chain.head().unwrap();
    (h.number, h.hash_slow())
}

async fn wait_for(nodes: &[&Node], height: u64, secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let heads: Vec<u64> = nodes.iter().map(|n| head(n).0).collect();
        if heads.iter().all(|h| *h >= height) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for height {height}: {heads:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn seven_validators_survive_two_failures() {
    let g = genesis();
    assert_eq!(g.dev_validators.len(), 7);
    let mut nodes: Vec<Node> = Vec::new();
    let mut boot: Vec<Multiaddr> = Vec::new();
    for i in 0..7u32 {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Chain::open(dir.path(), &g).unwrap());
        let cfg = chain.config().clone();
        let (net, events) = start_net(chain.clone(), boot.clone()).await;
        if boot.len() < 2 {
            boot.push(addr_of(&net).await);
        }
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
                state_dir: dir.path().join("consensus"),
            },
            miner: None,
        };
        let task = tokio::spawn(async move {
            if let Err(e) = v.run(events).await {
                eprintln!("validator {i}: {e:#}");
            }
        });
        nodes.push(Node { chain, net, task, _dir: dir });
    }

    // A non-validator follower that only trusts finality proofs.
    let fdir = tempfile::tempdir().unwrap();
    let fchain = Arc::new(Chain::open(fdir.path(), &g).unwrap());
    let (fnet, mut fevents) = start_net(fchain.clone(), boot.clone()).await;
    let follower = Follower::with_finality(
        fchain.clone(),
        fnet.clone(),
        Arc::new(Finality::new(fchain.clone())),
    );
    let ftask = tokio::spawn(async move {
        while let Some(ev) = fevents.recv().await {
            if let NetEvent::Announce { via, announce } = ev
                && let Err(e) = follower.on_announce(via, announce).await
            {
                eprintln!("follower: {e}");
            }
        }
    });
    let fnode = Node { chain: fchain, net: fnet, task: ftask, _dir: fdir };

    let all: Vec<&Node> = nodes.iter().collect();
    wait_for(&all, 5, 90).await;
    eprintln!(
        "all seven at height >= 5: {:?}",
        nodes.iter().map(|n| head(n).0).collect::<Vec<_>>()
    );

    // Stop two validators (2 of 7 < 1/3 of the weight).
    for n in nodes.drain(5..) {
        n.task.abort();
        n.net.shutdown().await;
    }
    let start = nodes.iter().map(|n| head(n).0).max().unwrap();
    let live: Vec<&Node> = nodes.iter().collect();
    wait_for(&live, start + 5, 120).await;

    // Every live validator agrees on the blocks they all have.
    let common = nodes.iter().map(|n| head(n).0).min().unwrap();
    let want =
        nodes[0].chain.store().reader().unwrap().header(common).unwrap().unwrap().hash_slow();
    for n in &nodes[1..] {
        let got = n.chain.store().reader().unwrap().header(common).unwrap().unwrap().hash_slow();
        assert_eq!(got, want, "validators disagree at height {common}");
    }

    // The follower catches up to a finalized block and agrees with the validators.
    wait_for(&[&fnode], common, 60).await;
    let got = fnode.chain.store().reader().unwrap().header(common).unwrap().unwrap().hash_slow();
    assert_eq!(got, want, "follower disagrees at height {common}");
    eprintln!(
        "final heads: {:?}, follower {}",
        nodes.iter().map(|n| head(n).0).collect::<Vec<_>>(),
        head(&fnode).0
    );

    for n in nodes.into_iter().chain([fnode]) {
        n.task.abort();
        n.net.shutdown().await;
    }
}
