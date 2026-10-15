//! ADR 0014 acceptance: on a dev PoS chain (7 genesis validators on 3 nodes, 6-block epochs),
//! validators offer user storage; a user's node hosts a bolt-vault file, the user pays a deal of
//! 3 copies, the 3 assigned validators' nodes fetch it, deal audits are certified as passed, a
//! copy is paid for its finished epochs, and another node reads the file back.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_chain::Chain;
use bolt_ipld::Cid;
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
async fn follower(g: &Genesis, boot: Vec<Multiaddr>) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let chain = Arc::new(Chain::open(dir.path(), g).unwrap());
    let (net, events) = start_net(chain.clone(), boot).await;
    let (mut events, srx) = boltchain::storage::split(events);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_file_is_kept_audited_paid_and_read_back() {
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
        let pool = Arc::new(TxPool::new(bolt_txpool::PoolConfig::new(
            cfg.chain_id,
            cfg.gas_limit,
            cfg.min_base_fee_wei,
        )));
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

    // Owners publish their validators' peers and offer 1 GiB each at 1 gwei per GiB per epoch.
    for (n, ids) in key_sets.iter().enumerate() {
        for i in ids {
            let id = i + 1;
            let peer = ISwarmStorage::setPeerCall {
                id,
                peerId: Bytes::from(nodes[n].net.peer_id().to_bytes()),
            }
            .abi_encode();
            submit(&nodes, &call_tx(&owner(*i), 0, SWARM, U256::ZERO, peer));
            let offer =
                ISwarmStorage::offerStorageCall { id, capacityMiB: 1024, minPrice: 1_000_000_000 }
                    .abi_encode();
            submit(&nodes, &call_tx(&owner(*i), 1, SWARM, U256::ZERO, offer));
        }
    }
    let c0 = nodes[0].chain.clone();
    wait_until("offers open", 60, || {
        view(&c0, SWARM, ISwarmStorage::offerListCall {}).len() == 7
            && (1..=7).all(|id| !view(&c0, SWARM, ISwarmStorage::peerOfCall { id }).is_empty())
    })
    .await;

    // The user's node (no validators) hosts a sealed file.
    let user_node = follower(&g, boot.clone()).await;
    let data: Vec<u8> = (0..700_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
    let (sk, pk) = bolt_vault::SecretKey::derive(b"user vault key");
    let sealed = bolt_vault::seal(
        &data,
        "notes.bin",
        "application/octet-stream",
        &[pk],
        &Default::default(),
    )
    .unwrap();
    let to_ipld = |c: &bolt_vault::Cid| Cid::try_from(c.to_bytes().as_slice()).unwrap();
    let mut blocks: Vec<(Cid, Vec<u8>)> = sealed
        .shards
        .iter()
        .chain([&sealed.manifest, &sealed.envelope])
        .map(|b| (to_ipld(&b.cid), b.data.clone()))
        .collect();
    let listed: Vec<Cid> = blocks.iter().map(|(c, _)| *c).collect();
    let sizes: Vec<(Cid, u64)> = blocks.iter().map(|(c, b)| (*c, b.len() as u64)).collect();
    let (root, idx, index_blocks) =
        bolt_ipld::deal::deal_index(&sizes, Some(to_ipld(&sealed.envelope.cid)));
    blocks.extend(index_blocks);
    user_node.storage.host(root, &blocks).unwrap();

    // The user pays 3 copies for 30 epochs.
    let user = funded();
    let price = 1_000_000_000u128;
    let per_epoch = (U256::from(price) * U256::from(idx.size.div_ceil(1 << 20)) + U256::from(1023))
        / U256::from(1024);
    let create = ISwarmStorage::createDealCall {
        root: Bytes::from(root.to_bytes()),
        blocks: idx.count,
        size: idx.size,
        replicas: 3,
        epochs: 30,
        price,
    };
    let value = per_epoch * U256::from(3 * 30);
    // createDeal draws and assigns 3 copies: more gas than `call_tx` gives.
    let mut t = TxEip1559 {
        chain_id: 1337,
        nonce: 0,
        gas_limit: 3_000_000,
        max_fee_per_gas: 5_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        to: TxKind::Call(SWARM),
        value,
        input: create.abi_encode().into(),
        ..Default::default()
    };
    let sig = user.sign_transaction_sync(&mut t).unwrap();
    let tx: TxEnvelope = t.into_signed(sig).into();
    submit(&nodes, &tx);
    wait_until("deal created", 60, || {
        view(&c0, SWARM, ISwarmStorage::dealCountCall {}) == U256::from(1)
    })
    .await;
    let slots = view(&c0, SWARM, ISwarmStorage::dealSlotsCall { id: U256::ZERO });
    let d = view(&c0, SWARM, ISwarmStorage::dealCall { id: U256::ZERO });
    eprintln!("deal 0: copies at {:?} from epoch {}", slots.providers, d.startEpoch);
    assert_eq!(slots.providers.len(), 3);

    // The nodes of the assigned validators fetch every block.
    let node_of = |id: u32| key_sets.iter().position(|ids| ids.contains(&(id - 1))).unwrap();
    let holders: Vec<usize> = slots.providers.iter().map(|p| node_of(*p)).collect();
    wait_until("providers fetched the deal", 120, || {
        holders.iter().all(|n| {
            let r = nodes[*n].chain.store().reader().unwrap();
            listed.iter().all(|c| r.ipld(c).unwrap().is_some())
        })
    })
    .await;

    // Deal audits are drawn from the next epoch on and certified as passed.
    let mut found = None;
    wait_until("a certified deal audit", 180, || {
        let cur = c0.rules().epoch_of(head(&nodes[0]) + 1);
        found = (d.startEpoch + 1..=cur).find_map(|e| {
            let kinds = view(&c0, SWARM, ISwarmStorage::taskKindsCall { epoch: e });
            let a = view(&c0, SWARM, ISwarmStorage::auditsCall { epoch: e });
            (0..kinds.len()).find(|t| kinds[*t] == 1 && a.states[*t] == 1).map(|t| (e, t))
        });
        found.is_some()
    })
    .await;
    let (e, t) = found.unwrap();
    let a = view(&c0, SWARM, ISwarmStorage::auditsCall { epoch: e });
    let kinds = view(&c0, SWARM, ISwarmStorage::taskKindsCall { epoch: e });
    eprintln!("epoch {e}: kinds {kinds:?} states {:?}", a.states);
    assert!(slots.providers.contains(&a.providers[t]));
    assert!(
        (0..kinds.len()).all(|t| kinds[t] != 1 || a.states[t] != 2),
        "no honest provider failed a deal audit"
    );

    // Anyone pays copy 0 for its finished epochs; the validator's owner is credited.
    let claim = ISwarmStorage::claimCall { id: U256::ZERO, slot: U256::ZERO }.abi_encode();
    submit(&nodes, &call_tx(&user, 1, SWARM, U256::ZERO, claim));
    let payee = owner(slots.providers[0] - 1).address();
    wait_until("copy 0 paid", 60, || {
        view(&c0, SWARM, ISwarmStorage::balanceOfCall { account: payee }) > U256::ZERO
    })
    .await;

    // Another validator node reads the file back through its storage service.
    let reader = (0..3).find(|n| !holders.contains(n)).unwrap_or(0);
    let s = nodes[reader].storage.clone();
    let env = s.fetch(&[to_ipld(&sealed.envelope.cid)], Some(0), None).await.unwrap();
    let envelope = env.values().next().unwrap().clone();
    let all = s.fetch(&listed, Some(0), None).await.unwrap();
    let (manifest, back) =
        bolt_vault::open(&envelope, &sk, |c| all.get(&to_ipld(c)).cloned()).unwrap();
    assert_eq!(manifest.name, "notes.bin");
    assert_eq!(back, data);

    for n in nodes.into_iter().chain([user_node]) {
        for t in n.tasks {
            t.abort();
        }
        n.net.shutdown().await;
    }
}
