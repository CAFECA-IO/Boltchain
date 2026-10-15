//! M4.5 acceptance (ADR 0007): a chain that starts with nobody special.
//!
//! Five nodes mine with RandomBOLT (two of them also hold validator keys) and ten follow. Four
//! validators register during the mining phase; once stake meets the thresholds for the required
//! epochs, PoS is scheduled and the committee takes over from the last mined block. Every node
//! ends on the same chain, a mined block after the switch is rejected, and a fresh node syncs from
//! genesis checking every seal and then the PoS finality proofs.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_chain::Chain;
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_primitives::{
    Genesis,
    bls::{BlsSecretKey, dev_key, pubkey_point, signature_point},
};
use bolt_rpc::HeadState;
use bolt_system::{abi::*, addresses::*};
use bolt_txpool::TxPool;
use boltchain::{
    miner::MinerConfig,
    validator::{Validator, ValidatorConfig},
};
use libp2p::{Multiaddr, identity};
use std::{sync::Arc, time::Duration};

const EPOCH: u64 = 8;
const MINERS: usize = 5;
const FOLLOWERS: usize = 10;
const STAKERS: u32 = 4;
const FIRST_KEY: u32 = 300;

fn genesis() -> Genesis {
    let mut g = Genesis::from_json(include_str!("../../../genesis/pow-dev.json")).unwrap();
    g.config.epoch_slots = EPOCH;
    g.config.committee_size = 8;
    g.config.pow.initial_difficulty = U256::from(128);
    g.config.pow.block_seconds = 3;
    g.config.pow.half_life_seconds = 60;
    g.config.pos_min_stakers = Some(STAKERS);
    g.config.pos_min_stake_bolt = Some(256);
    g.config.pos_streak_epochs = Some(2);
    g.validate().unwrap();
    g
}

fn bolt(n: u64) -> U256 {
    U256::from(n) * U256::from(10u64).pow(U256::from(18))
}

fn register_tx(k: u32) -> TxEnvelope {
    let signer: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse().unwrap();
    let sk = dev_key(FIRST_KEY + k);
    let pk = sk.public_key();
    let data = IStakingManager::registerCall {
        pubkey: Bytes::copy_from_slice(pk.as_slice()),
        pubkeyPoint: Bytes::copy_from_slice(&pubkey_point(&pk).unwrap()),
        pop: Bytes::copy_from_slice(&signature_point(&sk.proof_of_possession()).unwrap()),
        feeRecipient: Address::with_last_byte(0x70 + k as u8),
    }
    .abi_encode();
    let mut t = TxEip1559 {
        chain_id: 1338,
        nonce: k as u64,
        gas_limit: 800_000,
        max_fee_per_gas: 5_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        to: TxKind::Call(STAKING),
        value: bolt(100),
        input: data.into(),
        ..Default::default()
    };
    let sig = signer.sign_transaction_sync(&mut t).unwrap();
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
        Arc::new(bolt_sync::ChainBlocks(chain)),
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
    _dir: tempfile::TempDir,
}

async fn node(
    g: &Genesis,
    boot: &mut Vec<Multiaddr>,
    keys: Vec<BlsSecretKey>,
    miner: Option<Address>,
) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let chain = Arc::new(Chain::open(dir.path(), g).unwrap());
    let cfg = chain.config().clone();
    let (net, events) = start_net(chain.clone(), boot.clone()).await;
    if boot.len() < 3 {
        boot.push(addr_of(&net).await);
    }
    let pool = Arc::new(TxPool::new(bolt_txpool::PoolConfig::new(
        cfg.chain_id,
        cfg.gas_limit,
        cfg.min_base_fee_wei,
    )));
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
        miner: miner.map(|beneficiary| MinerConfig {
            beneficiary,
            threads: 1,
            mode: bolt_pow::Mode::Light,
            extra_data: Bytes::from_static(b"m4.5 test"),
        }),
    };
    let task = tokio::spawn(async move {
        if let Err(e) = v.run(events).await {
            eprintln!("node: {e:#}");
        }
    });
    Node { chain, pool, net, task, _dir: dir }
}

async fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn head(n: &Node) -> u64 {
    n.chain.head().unwrap().number
}

fn hash_at(n: &Node, h: u64) -> alloy_primitives::B256 {
    n.chain.store().reader().unwrap().header(h).unwrap().unwrap().hash_slow()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn mined_start_switches_to_pos() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,libmdbx=off".into()),
        )
        .with_test_writer()
        .try_init();
    let g = genesis();
    let mut boot = Vec::new();
    let mut miners = Vec::new();
    for i in 0..MINERS {
        // Nodes 0 and 1 also hold two validator keys each.
        let keys = if i < 2 {
            (0..2).map(|j| dev_key(FIRST_KEY + 2 * i as u32 + j)).collect()
        } else {
            vec![]
        };
        miners.push(node(&g, &mut boot, keys, Some(Address::with_last_byte(0x10 + i as u8))).await);
    }
    let mut followers = Vec::new();
    for _ in 0..FOLLOWERS {
        followers.push(node(&g, &mut boot, vec![], None).await);
    }

    // Mining phase: blocks come, rewards go to several miners.
    wait_until("block 2", 120, || miners.iter().all(|n| head(n) >= 2)).await;
    for k in 0..STAKERS {
        let raw = register_tx(k).encoded_2718();
        for n in &miners {
            let r = n.chain.store().reader().unwrap();
            let _ = n.pool.add_raw(&raw, &HeadState(&r));
        }
    }
    let c0 = miners[0].chain.clone();
    wait_until("registrations", 120, || {
        bolt_system::queries::call(
            &bolt_store::StateView::latest(&c0.store().reader().unwrap()),
            1338,
            STAKING,
            IStakingManager::countCall {},
        )
        .unwrap()
            == STAKERS
    })
    .await;
    let registered = head(&miners[0]);
    eprintln!("validators registered by block {registered}");
    assert!(registered < EPOCH, "registration in epoch 0");

    // PoS is scheduled once the thresholds held at two epoch starts (blocks 9 and 17): the first
    // PoS epoch is 4, the terminal mined block is 32.
    wait_until("PoS scheduled", 240, || c0.phase().unwrap().pos_epoch.is_some()).await;
    let phase = c0.phase().unwrap();
    assert_eq!(phase.pos_epoch, Some(4));
    let terminal = phase.terminal_height(c0.rules()).unwrap();
    assert_eq!(terminal, 4 * EPOCH);

    // The committee takes over and finalizes blocks after the terminal block.
    let target = terminal + 6;
    let all: Vec<&Node> = miners.iter().chain(followers.iter()).collect();
    let mut last = std::time::Instant::now();
    wait_until("PoS blocks on every node", 300, || {
        if last.elapsed() > Duration::from_secs(10) {
            eprintln!("heads: {:?}", all.iter().map(|n| head(n)).collect::<Vec<_>>());
            last = std::time::Instant::now();
        }
        all.iter().all(|n| head(n) >= target)
    })
    .await;
    let common = all.iter().map(|n| head(n)).min().unwrap();
    for n in &all[1..] {
        assert_eq!(hash_at(n, common), hash_at(all[0], common), "nodes disagree at {common}");
    }
    let r = c0.store().reader().unwrap();
    let mut winners = std::collections::BTreeSet::new();
    for h in 1..=terminal {
        let header = r.header(h).unwrap().unwrap();
        assert!(!header.difficulty.is_zero(), "block {h} is mined");
        winners.insert(header.beneficiary);
    }
    for h in terminal + 1..=common {
        let header = r.header(h).unwrap().unwrap();
        assert!(header.difficulty.is_zero(), "block {h} is produced by the committee");
    }
    drop(r);
    eprintln!("{} distinct miners won blocks 1..={terminal}", winners.len());
    assert!(winners.len() >= 2, "mining is not a single party");

    // A mined block on top of the terminal block is invalid.
    let (_d, lone) = {
        let d = tempfile::tempdir().unwrap();
        let c = Chain::open(d.path(), &g).unwrap();
        (d, c)
    };
    for h in 1..=terminal {
        let (header, txs) = {
            let r = c0.store().reader().unwrap();
            let b = r.block(h).unwrap().unwrap();
            (b.header, b.transactions)
        };
        lone.import_mined(&header, txs, None).unwrap();
    }
    let parent = lone.head().unwrap();
    let mut forged = parent.clone();
    forged.parent_hash = parent.hash_slow();
    forged.number = parent.number + 1;
    forged.timestamp = parent.timestamp + 2;
    forged.difficulty = lone.difficulty_after(&parent).unwrap();
    assert!(lone.import_mined(&forged, vec![], None).is_err(), "mined block after the switch");

    // A fresh node syncs from genesis: seals for the mined part, proofs for the PoS part.
    let fresh = node(&g, &mut boot, vec![], None).await;
    let target = all.iter().map(|n| head(n)).min().unwrap();
    wait_until("fresh sync", 240, || head(&fresh) >= target).await;
    assert_eq!(hash_at(&fresh, target), hash_at(all[0], target));
    eprintln!("fresh node synced to {target} (terminal {terminal})");

    for n in miners.into_iter().chain(followers).chain([fresh]) {
        n.task.abort();
        n.net.shutdown().await;
    }
}
