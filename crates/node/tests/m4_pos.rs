//! M4 acceptance (ADR 0006): on a dev chain with 7 genesis validators (PoS from block 1), 100
//! validators register on chain during epoch 0 and every epoch (6 blocks) samples a new 16-seat
//! committee by stake. The 107 validator keys run on 5 nodes. A validator double-votes: the nodes detect it and
//! write evidence, the evidence is submitted as a transaction and the validator is slashed on
//! chain. A fresh follower then syncs from genesis across all epochs, trusting only finality
//! proofs (epoch by epoch).

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_chain::Chain;
use bolt_consensus::{BlsScheme, Message, Vote, vote_msg};
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_primitives::{
    Genesis,
    bls::{BlsSecretKey, dev_key, pubkey_point, signature_point},
};
use bolt_rpc::HeadState;
use bolt_store::StateView;
use bolt_sync::{ChainBlocks, Follower};
use bolt_system::{abi::*, addresses::*, queries};
use bolt_txpool::TxPool;
use boltchain::validator::{Finality, Validator, ValidatorConfig};
use libp2p::{Multiaddr, identity};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

const EPOCH: u64 = 6;
const STAKERS: u32 = 100;
const FIRST_STAKER_KEY: u32 = 100;
const NODES: usize = 5;

fn genesis() -> Genesis {
    let mut g = Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap();
    g.config.epoch_slots = EPOCH;
    g.config.committee_size = 16;
    // Genesis validators stake 100 BOLT each here, like an average new staker.
    for v in &mut g.dev_validators {
        v.stake_bolt = 100;
    }
    g
}

fn bolt(n: u64) -> U256 {
    U256::from(n) * U256::from(10u64).pow(U256::from(18))
}

fn account(i: usize) -> PrivateKeySigner {
    [
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    ][i]
        .parse()
        .unwrap()
}

fn call_tx(
    s: &PrivateKeySigner,
    nonce: u64,
    to: Address,
    value: U256,
    data: Vec<u8>,
    gas: u64,
) -> TxEnvelope {
    let mut t = TxEip1559 {
        chain_id: 1337,
        nonce,
        gas_limit: gas,
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

/// Staker k registers dev key FIRST_STAKER_KEY + k with 64 + (k mod 37) BOLT.
fn register_tx(k: u32) -> TxEnvelope {
    let sk = dev_key(FIRST_STAKER_KEY + k);
    let pk = sk.public_key();
    let data = IStakingManager::registerCall {
        pubkey: Bytes::copy_from_slice(pk.as_slice()),
        pubkeyPoint: Bytes::copy_from_slice(&pubkey_point(&pk).unwrap()),
        pop: Bytes::copy_from_slice(&signature_point(&sk.proof_of_possession()).unwrap()),
        feeRecipient: Address::with_last_byte(k as u8),
    }
    .abi_encode();
    call_tx(&account(0), k as u64, STAKING, bolt(64 + (k % 37) as u64), data, 800_000)
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
    pool: Arc<TxPool>,
    net: NetHandle,
    task: tokio::task::JoinHandle<()>,
    dir: tempfile::TempDir,
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

fn submit(nodes: &[Node], tx: &TxEnvelope) {
    // No transaction gossip yet: hand it to every node's pool (any leader may include it).
    let raw = tx.encoded_2718();
    for n in nodes {
        let r = n.chain.store().reader().unwrap();
        let _ = n.pool.add_raw(&raw, &HeadState(&r));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundred_validators_rotate_committees_and_equivocation_is_slashed() {
    let g = genesis();
    // 7 genesis keys + 100 staker keys, dealt round-robin to the nodes.
    let mut keys: Vec<Vec<BlsSecretKey>> = vec![Vec::new(); NODES];
    for i in 0..7u32 {
        keys[i as usize % NODES].push(dev_key(i));
    }
    for k in 0..STAKERS {
        keys[k as usize % NODES].push(dev_key(FIRST_STAKER_KEY + k));
    }

    let mut nodes: Vec<Node> = Vec::new();
    let mut boot: Vec<Multiaddr> = Vec::new();
    for keys in keys {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Chain::open(dir.path(), &g).unwrap());
        let cfg = chain.config().clone();
        let (net, events) = start_net(chain.clone(), boot.clone()).await;
        if boot.len() < 2 {
            boot.push(addr_of(&net).await);
        }
        let mut pcfg =
            bolt_txpool::PoolConfig::new(cfg.chain_id, cfg.gas_limit, cfg.min_base_fee_wei);
        pcfg.max_per_sender = 128; // one account registers all 100 validators
        let pool = Arc::new(TxPool::new(pcfg));
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
        let task = tokio::spawn(async move {
            if let Err(e) = v.run(events).await {
                eprintln!("validator: {e:#}");
            }
        });
        nodes.push(Node { chain, pool, net, task, dir });
    }
    let head = |n: &Node| n.chain.head().unwrap().number;

    // Epoch 0: the 100 validators register.
    wait_until("block 1", 60, || nodes.iter().all(|n| head(n) >= 1)).await;
    for k in 0..STAKERS {
        submit(&nodes, &register_tx(k));
    }
    let c0 = &nodes[0].chain;
    wait_until("100 registrations", 120, || {
        view(c0, STAKING, IStakingManager::countCall {}) == 7 + STAKERS
    })
    .await;
    let registered_at = head(&nodes[0]);
    eprintln!("100 validators registered by block {registered_at}");
    assert!(registered_at <= EPOCH, "registrations spilled past epoch 0");

    // Epochs 2..=5 are sampled by stake from all 107.
    wait_until("epoch 5 final", 240, || nodes.iter().all(|n| head(n) >= 6 * EPOCH)).await;
    let mut members_seen = BTreeSet::new();
    let mut committees = Vec::new();
    let (mut genesis_seats, mut all_seats) = (0u32, 0u32);
    for e in 2..=6u64 {
        let c = view(c0, CONSENSUS, IConsensusRegistry::committeeCall { epoch: e });
        assert_eq!(c.weights.iter().map(|w| *w as u32).sum::<u32>(), 16, "epoch {e}");
        for (id, w) in c.ids.iter().zip(&c.weights) {
            all_seats += *w as u32;
            if *id <= 7 {
                genesis_seats += *w as u32;
            }
        }
        members_seen.extend(c.ids.iter().copied());
        committees.push(c.ids);
    }
    // Genesis validators hold 700 of ~10,000 BOLT: no special weight.
    eprintln!("genesis validators held {genesis_seats} of {all_seats} seats in epochs 2-6");
    assert!(genesis_seats * 5 < all_seats, "genesis validators dominate");
    eprintln!("committees of epochs 2-6: {committees:?}");
    assert!(committees.windows(2).all(|w| w[0] != w[1]), "committees rotate");
    assert!(members_seen.len() > 30, "only {} distinct validators served", members_seen.len());
    // Everyone agrees on the chain so far.
    let h = nodes.iter().map(head).min().unwrap();
    let hash_at = |n: &Node, h: u64| {
        n.chain.store().reader().unwrap().header(h).unwrap().unwrap().hash_slow()
    };
    for n in &nodes[1..] {
        assert_eq!(hash_at(n, h), hash_at(&nodes[0], h));
    }

    // A committee member equivocates: two votes in the same round of the current epoch. Pick a
    // moment well inside an epoch so every node runs the same one.
    wait_until("mid-epoch", 30, || {
        let h = head(&nodes[0]);
        (1..=3).contains(&(h % EPOCH)) && nodes.iter().all(|n| head(n) / EPOCH == h / EPOCH)
    })
    .await;
    let epoch = g.config.epoch_slots.max(1);
    let epoch = (head(&nodes[0])) / epoch; // epoch_of(head + 1) for a head inside the epoch
    let c = view(c0, CONSENSUS, IConsensusRegistry::committeeCall { epoch });
    let (index, id) = c
        .ids
        .iter()
        .enumerate()
        .find(|(_, id)| **id > 7)
        .map(|(i, id)| (i as u16, *id))
        .expect("a staker on the committee");
    let sk = dev_key(FIRST_STAKER_KEY + id - 8); // ids 8.. were registered in key order
    let round = 999;
    // Published by a node that does not hold the key, so the holder receives votes it never sent.
    let holder = (id - 8) as usize % NODES; // staker keys were dealt round-robin
    let (publisher, witness) = ((holder + 1) % NODES, (holder + 2) % NODES);
    for block in [B256::repeat_byte(0xa1), B256::repeat_byte(0xb2)] {
        let v: Message<BlsScheme> = Message::Vote(Vote {
            epoch,
            round,
            block,
            height: 1,
            signer: index,
            sig: sk.sign(&vote_msg(1337, epoch, round, &block)),
        });
        let _ = nodes[publisher].net.publish_consensus(bolt_consensus::encode(&v)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Other nodes detect it and write the evidence transaction's calldata.
    let evidence_file = nodes[witness]
        .dir
        .path()
        .join("consensus")
        .join("evidence")
        .join(format!("{epoch}-{round}-{id}.json"));
    wait_until("evidence file", 30, || evidence_file.exists()).await;
    // The holder sees its key used elsewhere: doppelganger protection stops it signing.
    wait_until("doppelganger", 30, || bolt_primitives::metrics::DOPPELGANGER.get() == 1).await;
    eprintln!("node {holder} stopped signing: its key was used elsewhere");
    let ev: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_file).unwrap()).unwrap();
    let data: Bytes = ev["data"].as_str().unwrap().parse().unwrap();
    let reporter = account(1);
    let before = view(c0, STAKING, IStakingManager::validatorCall { id });
    submit(&nodes, &call_tx(&reporter, 0, CONSENSUS, U256::ZERO, data.to_vec(), 2_000_000));
    wait_until("slashing", 60, || {
        matches!(
            view(c0, STAKING, IStakingManager::validatorCall { id }).status,
            IStakingManager::Status::Slashed
        )
    })
    .await;
    let after = view(c0, STAKING, IStakingManager::validatorCall { id });
    eprintln!("validator {id} slashed: stake {} -> {}", before.stake, after.stake);
    assert_eq!(
        after.stake,
        before.stake - before.stake * U256::from(500) / U256::from(10_000),
        "5% on a first offence"
    );
    assert!(
        !view(c0, STAKING, IStakingManager::snapshotCall { minAge: 0 }).ids.contains(&id),
        "no longer eligible"
    );

    // A fresh follower syncs from genesis across all epochs, checking every epoch proof.
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
    let target = nodes.iter().map(head).min().unwrap();
    let mut last_log = std::time::Instant::now();
    wait_until("follower sync", 150, || {
        if last_log.elapsed() > Duration::from_secs(10) {
            eprintln!(
                "follower head {} / target {target}; validator heads {:?}",
                fchain.head().unwrap().number,
                nodes.iter().map(head).collect::<Vec<_>>()
            );
            last_log = std::time::Instant::now();
        }
        fchain.head().unwrap().number >= target
    })
    .await;
    assert_eq!(
        fchain.store().reader().unwrap().header(target).unwrap().unwrap().hash_slow(),
        hash_at(&nodes[0], target)
    );
    eprintln!(
        "follower synced to {target} (epoch {}) from genesis",
        fchain.rules().epoch_of(target)
    );

    ftask.abort();
    fnet.shutdown().await;
    for n in nodes {
        n.task.abort();
        n.net.shutdown().await;
    }
}
