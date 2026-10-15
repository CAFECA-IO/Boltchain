//! M4.6 acceptance (ADR 0007): the whole path A → B → C.
//!
//! Three nodes mine with RandomBOLT; validator keys are spread over two of the miners and a third,
//! non-mining node; two nodes only follow. Two validators register early: once stake meets the
//! phase-B thresholds (T1) for the required epochs, their committee starts finalizing mined
//! checkpoints while mining goes on. Two more register later; when stake meets T2, PoS starts
//! from the terminal block, which phase B has finalized, so the first PoS block carries its proof.
//!
//! Along the way: finality reaches every node through proofs; checkpoint voters are paid; and a
//! heavier private branch forking below a finalized checkpoint is refused, while a node without
//! that finality would have followed it.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_chain::{Chain, ChainError, pow::MinedOutcome};
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
use std::{sync::Arc, sync::atomic::AtomicBool, time::Duration};

const EPOCH: u64 = 8;
const FIRST_KEY: u32 = 400;

fn genesis() -> Genesis {
    let mut g = Genesis::from_json(include_str!("../../../genesis/pow-dev.json")).unwrap();
    g.config.epoch_slots = EPOCH;
    g.config.committee_size = 8;
    g.config.pow.initial_difficulty = U256::from(96);
    g.config.pow.block_seconds = 2;
    g.config.pow.half_life_seconds = 60;
    g.config.checkpoint_min_stakers = Some(2);
    g.config.checkpoint_min_stake_bolt = Some(128);
    g.config.checkpoint_depth = Some(3);
    g.config.pos_min_stakers = Some(4);
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
            extra_data: Bytes::from_static(b"m4.6 test"),
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

fn fin(n: &Node) -> u64 {
    n.chain.finalized().unwrap().map(|(h, _)| h).unwrap_or(0)
}

fn hash_at(n: &Node, h: u64) -> alloy_primitives::B256 {
    n.chain.store().reader().unwrap().header(h).unwrap().unwrap().hash_slow()
}

fn submit(nodes: &[&Node], tx: &TxEnvelope) {
    let raw = tx.encoded_2718();
    for n in nodes {
        let r = n.chain.store().reader().unwrap();
        let _ = n.pool.add_raw(&raw, &HeadState(&r));
    }
}

fn view<C: SolCall>(chain: &Chain, to: Address, c: C) -> C::Return {
    let r = chain.store().reader().unwrap();
    bolt_system::queries::call(&bolt_store::StateView::latest(&r), 1338, to, c).unwrap()
}

/// Copies canonical blocks `from..=to` of `src` into `dst`.
fn copy_blocks(src: &Chain, dst: &Chain, from: u64, to: u64) {
    for n in from..=to {
        let r = src.store().reader().unwrap();
        let b = r.block(n).unwrap().unwrap();
        let root = r.envelope_root(n).unwrap().unwrap();
        let env = bolt_ipld::Envelope::decode(&r.ipld(&root).unwrap().unwrap()).unwrap();
        drop(r);
        dst.import_mined_with_cert(&b.header, b.transactions, Some(root), env.qc).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn mining_then_stake_finality_then_pos() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,libmdbx=off".into()),
        )
        .with_test_writer()
        .try_init();
    let g = genesis();
    let mut boot = Vec::new();
    let m0 =
        node(&g, &mut boot, vec![dev_key(FIRST_KEY)], Some(Address::with_last_byte(0x10))).await;
    let m1 = node(&g, &mut boot, vec![dev_key(FIRST_KEY + 1)], Some(Address::with_last_byte(0x11)))
        .await;
    let m2 = node(&g, &mut boot, vec![], Some(Address::with_last_byte(0x12))).await;
    let v3 = node(&g, &mut boot, vec![dev_key(FIRST_KEY + 2), dev_key(FIRST_KEY + 3)], None).await;
    let f0 = node(&g, &mut boot, vec![], None).await;
    let f1 = node(&g, &mut boot, vec![], None).await;
    let miners = [&m0, &m1, &m2];
    let all = [&m0, &m1, &m2, &v3, &f0, &f1];
    let heads = || all.iter().map(|n| head(n)).collect::<Vec<_>>();
    let fins = || all.iter().map(|n| fin(n)).collect::<Vec<_>>();

    // Phase A: two validators register in epoch 0.
    wait_until("block 1", 120, || head(&m0) >= 1).await;
    for k in 0..2 {
        submit(&miners, &register_tx(k));
    }
    let c0 = m0.chain.clone();
    wait_until("T1 registrations", 120, || view(&c0, STAKING, IStakingManager::countCall {}) == 2)
        .await;
    assert!(head(&m0) < EPOCH, "registered in epoch 0");

    // T1 held at blocks 9 and 17: phase B from epoch 4 (blocks 33..40).
    wait_until("phase B scheduled", 240, || c0.phase().unwrap().checkpoint_epoch.is_some()).await;
    let phase = c0.phase().unwrap();
    assert_eq!(phase.checkpoint_epoch, Some(4));
    assert_eq!(phase.pos_epoch, None);

    // The other two register once phase B is under way (block 33+).
    wait_until("block 34", 300, || head(&m0) >= 34).await;
    for k in 2..4 {
        submit(&miners, &register_tx(k));
    }

    // Checkpoints become final on every node, followers included, while mining goes on.
    let mut last = std::time::Instant::now();
    wait_until("checkpoints of epoch 4", 300, || {
        if last.elapsed() > Duration::from_secs(10) {
            eprintln!("heads {:?} finalized {:?}", heads(), fins());
            last = std::time::Instant::now();
        }
        all.iter().all(|n| fin(n) >= 4 * EPOCH + 3)
    })
    .await;
    eprintln!("phase B running: heads {:?} finalized {:?}", heads(), fins());

    // A heavier private branch forking below the finalized checkpoint is refused; a node that
    // had not learned about that finality would have followed it.
    let f = fin(&f0);
    let fork = f - 2;
    let lone = {
        let d = tempfile::tempdir().unwrap();
        let c = Chain::open(d.path(), &g).unwrap();
        (d, c)
    };
    copy_blocks(&f0.chain, &lone.1, 1, fork);
    let control = {
        let d = tempfile::tempdir().unwrap();
        let c = Chain::open(d.path(), &g).unwrap();
        (d, c)
    };
    let control_head = head(&f0);
    copy_blocks(&f0.chain, &control.1, 1, control_head);
    let target_td = control.1.head_total_difficulty().unwrap();
    let mut branch = Vec::new();
    while lone.1.head_total_difficulty().unwrap() <= target_td {
        let parent = lone.1.head().unwrap();
        let t = lone
            .1
            .build_template(
                vec![],
                parent.timestamp + 1,
                Address::repeat_byte(0xee),
                Bytes::new(),
                vec![],
            )
            .unwrap();
        let key = lone.1.seal_key(&parent.hash_slow(), parent.number + 1).unwrap();
        let stop = AtomicBool::new(false);
        let seal = bolt_pow::seal_hash(&t.header);
        let (nonce, _) = lone
            .1
            .pow()
            .search(&key, &seal, t.header.difficulty, 0, 1, u64::MAX, &stop)
            .unwrap()
            .unwrap();
        let (h, _) = lone.1.seal_and_import(&t, nonce).unwrap();
        branch.push(h);
    }
    eprintln!("private branch of {} blocks from {fork} (finalized {f})", branch.len());
    let mut refused = None;
    for h in &branch {
        if let Err(e) = f0.chain.import_mined(h, vec![], None) {
            refused = Some(e);
            break;
        }
    }
    assert!(matches!(refused, Some(ChainError::DeepReorg(_))), "{refused:?}");
    assert!(fin(&f0) >= f, "finality unchanged");
    let mut outcome = None;
    for h in &branch {
        outcome = Some(control.1.import_mined(h, vec![], None).unwrap());
    }
    assert!(matches!(outcome, Some(MinedOutcome::Reorged { .. })), "{outcome:?}");

    // T2 held at blocks 41 and 49: PoS from epoch 8; the terminal block is 64.
    wait_until("PoS scheduled", 300, || c0.phase().unwrap().pos_epoch.is_some()).await;
    let phase = c0.phase().unwrap();
    assert_eq!(phase.pos_epoch, Some(8));
    let terminal = phase.terminal_height(c0.rules()).unwrap();
    assert_eq!(terminal, 8 * EPOCH);
    // Epoch 4's checkpoint voters were paid at block 41 (40% of the epoch's consensus emission).
    let paid: U256 = [1u32, 2]
        .iter()
        .map(|id| view(&c0, REWARDS, IRewardDistributor::rewardsCall { id: *id }))
        .sum();
    eprintln!("checkpoint voters earned {paid} wei");
    assert!(paid > U256::ZERO, "voters paid");

    // PoS: every node follows the committee's blocks after the finalized terminal block.
    let target = terminal + 5;
    wait_until("PoS blocks on every node", 300, || {
        if last.elapsed() > Duration::from_secs(10) {
            eprintln!("heads {:?} finalized {:?}", heads(), fins());
            last = std::time::Instant::now();
        }
        all.iter().all(|n| head(n) >= target)
    })
    .await;
    let common = all.iter().map(|n| head(n)).min().unwrap();
    for n in &all[1..] {
        assert_eq!(hash_at(n, common), hash_at(all[0], common), "nodes disagree at {common}");
    }
    assert!(all.iter().all(|n| fin(n) == terminal), "terminal finalized by phase B: {:?}", fins());
    let r = c0.store().reader().unwrap();
    for h in terminal + 1..=common {
        assert!(r.header(h).unwrap().unwrap().difficulty.is_zero(), "block {h} is PoS");
    }
    // The first PoS block carries the proof that the terminal block is final.
    let root = r.envelope_root(terminal + 1).unwrap().unwrap();
    let env = bolt_ipld::Envelope::decode(&r.ipld(&root).unwrap().unwrap()).unwrap();
    assert!(
        matches!(
            bolt_consensus::decode_cert::<bolt_consensus::BlsScheme>(&env.qc),
            Some(bolt_consensus::Cert::Epoch(_))
        ),
        "first PoS block certifies the terminal block"
    );
    drop(r);

    // A fresh node syncs everything: seals and checkpoint proofs, then PoS proofs.
    let fresh = node(&g, &mut boot, vec![], None).await;
    let target = all.iter().map(|n| head(n)).min().unwrap();
    wait_until("fresh sync", 240, || head(&fresh) >= target).await;
    assert_eq!(hash_at(&fresh, target), hash_at(all[0], target));
    eprintln!("fresh node synced to {target} (terminal {terminal})");

    for n in [m0, m1, m2, v3, f0, f1, fresh] {
        n.task.abort();
        n.net.shutdown().await;
    }
}
