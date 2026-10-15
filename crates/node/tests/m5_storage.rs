//! M5 acceptance (ADR 0009): on a dev PoS chain (7 genesis validators on 3 nodes, 6-block epochs,
//! a 1-epoch recent window) with steady transfers:
//!
//! - every epoch's index is recorded on chain;
//! - validators publish their peers, audit each other's history shards, certify the results and
//!   the passes earn storage rewards;
//! - a node without validators prunes old bodies, while assigned validators keep them;
//! - a fresh node starts from an announced state snapshot (trusting only a checkpoint hash) and
//!   catches up with the chain;
//! - an epoch's CAR is served by a validator's HTTP gateway and verifies block by block.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_chain::Chain;
use bolt_ipld::{Cid, Envelope, car, history::EpochIndex};
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_primitives::{
    Genesis,
    bls::{BlsSecretKey, dev_eth_key, dev_key},
    genesis::GenesisAccount,
};
use bolt_rpc::HeadState;
use bolt_store::StateView;
use bolt_sync::{ChainBlocks, Follower};
use bolt_system::{abi::*, addresses::*, queries};
use bolt_txpool::TxPool;
use boltchain::{
    storage::{Storage, StorageConfig},
    validator::{Finality, Validator, ValidatorConfig},
};
use libp2p::{Multiaddr, identity};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EPOCH: u64 = 6;

fn owner(i: u32) -> PrivateKeySigner {
    PrivateKeySigner::from_slice(&dev_eth_key(i)).unwrap()
}

fn genesis() -> Genesis {
    let mut g = Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap();
    g.config.epoch_slots = EPOCH;
    g.config.committee_size = 16;
    g.config.history_recent_epochs = Some(1);
    // Validator owners pay for their `setPeer` transactions.
    for i in 0..7 {
        g.alloc.insert(
            owner(i).address(),
            GenesisAccount { balance: U256::from(10u128.pow(19)), ..Default::default() },
        );
    }
    g
}

fn funded() -> PrivateKeySigner {
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse().unwrap()
}

fn call_tx(
    s: &PrivateKeySigner,
    nonce: u64,
    to: Address,
    value: U256,
    data: Vec<u8>,
) -> TxEnvelope {
    let mut t = TxEip1559 {
        chain_id: 1337,
        nonce,
        gas_limit: 300_000,
        max_fee_per_gas: 5_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        to: TxKind::Call(to),
        value,
        input: data.into(),
        ..Default::default()
    };
    let sig = s.sign_transaction_sync(&mut t).unwrap();
    t.into_signed(sig).into()
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

fn view<C: SolCall>(chain: &Chain, to: Address, c: C) -> C::Return {
    let r = chain.store().reader().unwrap();
    queries::call(&StateView::latest(&r), 1337, to, c).unwrap()
}

async fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

struct Node {
    chain: Arc<Chain>,
    pool: Option<Arc<TxPool>>,
    net: NetHandle,
    storage: Arc<Storage>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

fn submit(nodes: &[Node], tx: &TxEnvelope) {
    let raw = tx.encoded_2718();
    for n in nodes {
        if let Some(pool) = &n.pool {
            let r = n.chain.store().reader().unwrap();
            let _ = pool.add_raw(&raw, &HeadState(&r));
        }
    }
}

/// A node syncing with finality proofs (no validator keys), with the storage service.
async fn follower(
    g: &Genesis,
    boot: Vec<Multiaddr>,
    checkpoint: Option<(u64, alloy_primitives::B256)>,
) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let chain = Arc::new(Chain::open(dir.path(), g).unwrap());
    let (net, events) = start_net(chain.clone(), boot).await;
    let (mut events, mut srx) = boltchain::storage::split(events);
    if let Some((number, hash)) = checkpoint {
        tokio::time::timeout(
            Duration::from_secs(60),
            boltchain::storage::checkpoint_sync(&chain, &net, number, hash, None, &mut srx),
        )
        .await
        .expect("checkpoint sync in time")
        .unwrap();
    }
    let storage = Storage::new(chain.clone(), net.clone(), StorageConfig::default());
    let s = tokio::spawn(storage.clone().run(srx));
    let f =
        Follower::with_finality(chain.clone(), net.clone(), Arc::new(Finality::new(chain.clone())));
    let t = tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if let NetEvent::Announce { via, announce } = ev
                && let Err(e) = f.on_announce(via, announce).await
            {
                eprintln!("follower: {e}");
            }
        }
    });
    Node { chain, pool: None, net, storage, tasks: vec![s, t], _dir: dir }
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, buf[split + 4..].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_is_indexed_audited_pruned_and_snapshots_bootstrap_new_nodes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
    let g = genesis();
    let key_sets: Vec<Vec<u32>> = vec![vec![0, 3, 6], vec![1, 4], vec![2, 5]];
    let mut nodes: Vec<Node> = Vec::new();
    let mut boot: Vec<Multiaddr> = Vec::new();
    for ids in &key_sets {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Chain::open(dir.path(), &g).unwrap());
        let cfg = chain.config().clone();
        let (net, events) = start_net(chain.clone(), boot.clone()).await;
        boot.push(addr_of(&net).await);
        let (events, srx) = boltchain::storage::split(events);
        let keys: Vec<BlsSecretKey> = ids.iter().map(|i| dev_key(*i)).collect();
        let mut pcfg =
            bolt_txpool::PoolConfig::new(cfg.chain_id, cfg.gas_limit, cfg.min_base_fee_wei);
        pcfg.max_per_sender = 256;
        let pool = Arc::new(TxPool::new(pcfg));
        let storage = Storage::new(
            chain.clone(),
            net.clone(),
            StorageConfig { keys: keys.clone(), ..Default::default() },
        );
        let s = tokio::spawn(storage.clone().run(srx));
        let v = Validator {
            chain: chain.clone(),
            pool: pool.clone(),
            net: net.clone(),
            keys,
            cfg: ValidatorConfig {
                slot_ms: 1000,
                base_timeout_ms: 3000,
                state_dir: dir.path().join("consensus"),
            },
            miner: None,
        };
        let t = tokio::spawn(async move {
            if let Err(e) = v.run(events).await {
                eprintln!("validator: {e:#}");
            }
        });
        nodes.push(Node { chain, pool: Some(pool), net, storage, tasks: vec![s, t], _dir: dir });
    }
    let head = |n: &Node| n.chain.head().unwrap().number;
    wait_until("block 1", 60, || nodes.iter().all(|n| head(n) >= 1)).await;

    // Owners publish the peer each validator serves history from.
    for (n, ids) in key_sets.iter().enumerate() {
        for i in ids {
            let data = ISwarmStorage::setPeerCall {
                id: i + 1,
                peerId: Bytes::from(nodes[n].net.peer_id().to_bytes()),
            }
            .abi_encode();
            submit(&nodes, &call_tx(&owner(*i), 0, SWARM, U256::ZERO, data));
        }
    }
    // Steady transfers so blocks have bodies.
    let feeder_nodes: Vec<(Arc<Chain>, Arc<TxPool>)> =
        nodes.iter().map(|n| (n.chain.clone(), n.pool.clone().unwrap())).collect();
    let feeder = tokio::spawn(async move {
        let s = funded();
        for nonce in 0.. {
            let tx = call_tx(&s, nonce, Address::with_last_byte(0x77), U256::from(1), vec![]);
            let raw = tx.encoded_2718();
            for (c, p) in &feeder_nodes {
                let r = c.store().reader().unwrap();
                let _ = p.add_raw(&raw, &HeadState(&r));
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
    });
    let c0 = nodes[0].chain.clone();
    wait_until("peers registered", 60, || {
        (1..=7).all(|id| !view(&c0, SWARM, ISwarmStorage::peerOfCall { id }).is_empty())
    })
    .await;

    // A node without validators follows from genesis (it will prune).
    let pruner = follower(&g, boot.clone(), None).await;

    // Epoch indexes, audits and storage rewards.
    let mut last = std::time::Instant::now();
    wait_until("epoch 4 indexed", 120, || {
        if last.elapsed() > Duration::from_secs(10) {
            last = std::time::Instant::now();
            eprintln!(
                "heads {:?}, pruner {}",
                nodes.iter().map(head).collect::<Vec<_>>(),
                head(&pruner)
            );
        }
        view(&c0, SWARM, ISwarmStorage::indexedEpochsCall {}) >= 4
    })
    .await;
    let idx0 = view(&c0, SWARM, ISwarmStorage::epochIndexCall { epoch: 0 });
    let idx0 = Cid::try_from(idx0.as_ref()).unwrap();
    let mut passed_epoch = None;
    wait_until("a certified audit", 120, || {
        let cur = c0.rules().epoch_of(head(&nodes[0]) + 1);
        passed_epoch = (2..=cur)
            .find(|e| !view(&c0, SWARM, ISwarmStorage::passedCall { epoch: *e }).is_empty());
        passed_epoch.is_some()
    })
    .await;
    let e = passed_epoch.unwrap();
    let a = view(&c0, SWARM, ISwarmStorage::auditsCall { epoch: e });
    eprintln!("audits of epoch {e}: providers {:?} states {:?}", a.providers, a.states);
    assert!(a.states.iter().all(|s| *s != 2), "no honest provider failed");
    let provider = view(&c0, SWARM, ISwarmStorage::passedCall { epoch: e })[0];
    // Settled at the end of epoch e: the provider's rewards include a storage share.
    wait_until("storage settlement", 60, || head(&nodes[0]) > c0.rules().epoch_end(e) + 1).await;
    let rewards = view(&c0, REWARDS, IRewardDistributor::rewardsCall { id: provider });
    assert!(rewards > U256::ZERO);
    eprintln!("provider {provider} passed in epoch {e}; rewards {rewards}");

    // Pruning: the node without validators drops epoch 0's bodies; validators (all assigned
    // with 7 < 16 replicas) keep them.
    wait_until("pruner prunes epoch 0", 120, || {
        let r = pruner.chain.store().reader().unwrap();
        head(&pruner) > 3 * EPOCH && !r.has_body(1).unwrap()
    })
    .await;
    assert!(nodes.iter().all(|n| n.chain.store().reader().unwrap().has_body(1).unwrap()));
    assert!(nodes.iter().all(|n| n.chain.missing_epoch_data(0).unwrap().is_empty()));

    // Snapshots: a fresh node starts from the latest announced one, trusting only its hash.
    // Take the newest announced snapshot as soon as it appears (nodes keep the last two).
    let newest = |n: &Node| {
        n.storage.seen_snapshots().iter().map(|(_, s)| s.clone()).max_by_key(|s| s.number)
    };
    let before = newest(&nodes[0]).map(|s| s.number).unwrap_or(0);
    wait_until("a new final snapshot", 60, || newest(&nodes[0]).is_some_and(|s| s.number > before))
        .await;
    let snap = newest(&nodes[0]).unwrap();
    let trusted = c0.store().reader().unwrap().block_hash(snap.number).unwrap().unwrap();
    assert_eq!(snap.hash, trusted.to_vec());
    let fresh = follower(&g, boot.clone(), Some((snap.number, trusted))).await;
    assert_eq!(fresh.chain.store().reader().unwrap().base().unwrap(), snap.number);
    let target = head(&nodes[0]) + 2;
    wait_until("fresh node catches up", 90, || head(&fresh) >= target).await;
    let hash_at = |n: &Node, h: u64| n.chain.store().reader().unwrap().block_hash(h).unwrap();
    assert_eq!(hash_at(&fresh, target), hash_at(&nodes[0], target));
    // Before the checkpoint it holds headers (the BLOCKHASH window) but no bodies or state.
    assert_eq!(hash_at(&fresh, 1), hash_at(&nodes[0], 1));
    assert!(!fresh.chain.store().reader().unwrap().has_body(1).unwrap());
    assert!(!fresh.chain.store().reader().unwrap().history_covers(snap.number - 1).unwrap());
    eprintln!("fresh node started at block {} and caught up to {target}", snap.number);

    // Gateway: epoch 0 as a CAR from a validator.
    let gw = boltchain::gateway::start("127.0.0.1:0".parse().unwrap(), nodes[1].chain.clone())
        .await
        .unwrap();
    let (status, body) = http_get(gw, "/history/epoch/0.car").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (roots, blocks) = car::read(&body).unwrap(); // verifies every block
    assert_eq!(roots, vec![idx0]);
    let get = |c: &Cid| blocks.iter().find(|(k, _)| k == c).map(|(_, v)| v.clone());
    let idx = EpochIndex::decode(&get(&idx0).unwrap()).unwrap();
    assert_eq!((idx.first, idx.count), (1, EPOCH));
    let r = nodes[1].chain.store().reader().unwrap();
    let mut chunks = 0;
    for h in 1..=EPOCH {
        let root = r.envelope_root(h).unwrap().unwrap();
        let env = Envelope::decode(&get(&root).expect("envelope in the CAR")).unwrap();
        let block = bolt_ipld::decode_block(env, get).expect("complete block in the CAR");
        assert_eq!(block.header.hash_slow(), r.block_hash(h).unwrap().unwrap());
        chunks += block.envelope.chunks.len();
    }
    drop(r);
    eprintln!("epoch 0 CAR: {} blocks, {} bytes, {chunks} body chunks", blocks.len(), body.len());
    let (status, raw) = http_get(gw, &format!("/ipfs/{idx0}?format=raw")).await;
    assert_eq!((status, raw), (200, get(&idx0).unwrap()));
    // The pruned node's gateway no longer has epoch 0.
    let gw2 = boltchain::gateway::start("127.0.0.1:0".parse().unwrap(), pruner.chain.clone())
        .await
        .unwrap();
    assert_eq!(http_get(gw2, "/history/epoch/0.car").await.0, 404);

    feeder.abort();
    for n in nodes.into_iter().chain([pruner, fresh]) {
        for t in n.tasks {
            t.abort();
        }
        n.net.shutdown().await;
    }
}
