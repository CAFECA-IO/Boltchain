//! ADR 0011 verifier panels: on a dev PoS chain (7 genesis validators on 3 nodes, 6-block epochs)
//! a provider registers, takes a job and delivers; the requester disputes; the first block of the
//! next epoch assigns the dispute to a verifier panel; the validators' judges decide, their votes
//! form a certificate that a block carries, and the chain records the verdict (the requester is
//! refunded with the provider's slashed bond).

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
    bls::{BlsSecretKey, dev_eth_key, dev_key},
    genesis::GenesisAccount,
};
use bolt_rpc::HeadState;
use bolt_store::StateView;
use bolt_sync::ChainBlocks;
use bolt_system::{abi::*, addresses::*, queries};
use bolt_txpool::TxPool;
use boltchain::{
    storage::{DisputedJob, Judge, Storage, StorageConfig},
    validator::{Validator, ValidatorConfig},
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
    _storage: Arc<Storage>,
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

/// Judges every dispute: the provider is at fault.
#[derive(Debug)]
struct AlwaysFault;

impl Judge for AlwaysFault {
    fn judge(&self, job: &DisputedJob) -> Option<bool> {
        assert!(!job.output.is_empty());
        Some(true)
    }
}

fn tx(s: &PrivateKeySigner, nonce: u64, value: U256, data: Vec<u8>) -> TxEnvelope {
    tx_to(s, nonce, COMPUTE, value, data)
}

fn tx_to(s: &PrivateKeySigner, nonce: u64, to: Address, value: U256, data: Vec<u8>) -> TxEnvelope {
    let mut t = TxEip1559 {
        chain_id: 1337,
        nonce,
        gas_limit: 1_000_000,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dispute_is_decided_by_the_verifier_panel() {
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
            StorageConfig {
                keys: keys.clone(),
                verifier: Some(Arc::new(AlwaysFault)),
                ..Default::default()
            },
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
        nodes.push(Node {
            chain,
            pool: Some(pool),
            net,
            _storage: storage,
            tasks: vec![s, t],
            _dir: dir,
        });
    }
    let head = |n: &Node| n.chain.head().unwrap().number;
    wait_until("block 1", 60, || nodes.iter().all(|n| head(n) >= 1)).await;
    let c0 = nodes[0].chain.clone();

    // A provider (validator 0's owner account, funded at genesis) registers; the requester posts
    // a 2 BOLT job for it; the provider accepts and delivers.
    let provider = owner(0);
    let requester = funded();
    let reg = IComputeMarket::registerCall {
        encKey: alloy_primitives::B256::repeat_byte(1),
        peerId: Bytes::from_static(b"provider"),
    };
    submit(&nodes, &tx(&provider, 0, U256::ZERO, reg.abi_encode()));
    let now = c0.head().unwrap().timestamp;
    let post = IComputeMarket::postCall {
        provider_: provider.address(),
        model: 1,
        input: Bytes::from_static(b"input-cid"),
        priceIn: 10u128.pow(18),
        priceOut: 10u128.pow(18),
        maxIn: 1000,
        maxOut: 1000,
        deadline: now + 3600,
        window: 3600,
        relayFee: 0,
    };
    let bolt = U256::from(10u128.pow(18));
    let model = IModelRegistry::registerCall {
        name: "m".into(),
        weights: Bytes::from_static(b"w"),
        tokenizer: Bytes::new(),
        runtime: "r".into(),
        parameters: 1,
        vramMiB: 1,
    };
    submit(&nodes, &tx_to(&requester, 0, MODELS, U256::ZERO, model.abi_encode()));
    submit(&nodes, &tx(&requester, 1, bolt * U256::from(2), post.abi_encode()));
    wait_until("job posted", 60, || {
        view(&c0, COMPUTE, IComputeMarket::jobCountCall {}) == U256::from(1)
    })
    .await;
    let id = U256::ZERO;
    submit(&nodes, &tx(&provider, 1, U256::ZERO, IComputeMarket::acceptCall { id }.abi_encode()));
    let deliver = IComputeMarket::deliverCall {
        id,
        output: Bytes::from_static(b"output-cid"),
        tokensIn: 100,
        tokensOut: 200,
    };
    submit(&nodes, &tx(&provider, 2, U256::ZERO, deliver.abi_encode()));
    wait_until("job delivered", 60, || {
        view(&c0, COMPUTE, IComputeMarket::jobCall { id }).state == 3
    })
    .await;

    // The requester disputes; the next epoch's first block assigns a verifier panel.
    let dispute = IComputeMarket::disputeCall { id, reason: Bytes::from_static(b"reason-cid") };
    submit(&nodes, &tx(&requester, 2, bolt, dispute.abi_encode()));
    wait_until("panel assigned", 60, || {
        view(&c0, COMPUTE, IComputeMarket::disputesCall { id }).panelEpoch != 0
    })
    .await;
    let d = view(&c0, COMPUTE, IComputeMarket::disputesCall { id });
    let panel = view(&c0, COMPUTE, IComputeMarket::panelCall { epoch: d.panelEpoch });
    eprintln!("dispute assigned to the panel of epoch {}: {panel:?}", d.panelEpoch);
    assert!(!panel.is_empty());

    // The judges find the provider at fault: the certified verdict refunds the requester.
    wait_until("verdict recorded", 60, || {
        view(&c0, COMPUTE, IComputeMarket::jobCall { id }).state == 6
    })
    .await;
    let back = view(&c0, COMPUTE, IComputeMarket::balanceOfCall { account: requester.address() });
    // Escrow (2 BOLT) and deposit (1 BOLT) come back; the provider had no bond to slash yet.
    assert_eq!(back, bolt * U256::from(3));
    // Every node reached the same state.
    let target = head(&nodes[0]) + 1;
    wait_until("nodes agree", 30, || nodes.iter().all(|n| head(n) >= target)).await;
    for n in &nodes[1..] {
        assert_eq!(view(&n.chain, COMPUTE, IComputeMarket::jobCall { id }).state, 6);
    }

    for n in nodes {
        for t in n.tasks {
            t.abort();
        }
        n.net.shutdown().await;
    }
}
