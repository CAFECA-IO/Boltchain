//! M6: transactions admitted by one node reach every other node's pool by gossip (found on the
//! public testnet: without it a transaction waited until the node that received it produced a
//! block).

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use bolt_chain::Chain;
use bolt_net::{NetConfig, NetHandle};
use bolt_primitives::{Genesis, bls::dev_key};
use bolt_rpc::HeadState;
use bolt_sync::ChainBlocks;
use bolt_txpool::TxPool;
use boltchain::validator::{Validator, ValidatorConfig};
use libp2p::{Multiaddr, identity};
use std::{sync::Arc, time::Duration};

async fn addr_of(net: &NetHandle) -> Multiaddr {
    loop {
        if let Some(a) = net.listen_addrs().await.into_iter().next() {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn tx(nonce: u64) -> TxEnvelope {
    let s: PrivateKeySigner =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse().unwrap();
    let mut t = TxEip1559 {
        chain_id: 1337,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 5_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        to: TxKind::Call(Address::with_last_byte(9)),
        value: U256::from(1),
        ..Default::default()
    };
    let sig = s.sign_transaction_sync(&mut t).unwrap();
    t.into_signed(sig).into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transactions_are_gossiped_to_every_pool() {
    let mut g = Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap();
    g.config.epoch_slots = 32;
    g.config.committee_size = 16;
    let mut nodes = Vec::new();
    let mut boot = Vec::new();
    let mut dirs = Vec::new();
    for keys in [vec![0, 1, 2, 3], vec![4, 5, 6]] {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Chain::open(dir.path(), &g).unwrap());
        let (net, events) = bolt_net::start(
            NetConfig {
                chain_id: 1337,
                keypair: identity::Keypair::generate_ed25519(),
                listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
                bootnodes: boot.clone(),
                producer: None,
                fork_id: chain.fork_id().unwrap().to_string(),
                fork_check: None,
                relay_server: false,
                agent: String::new(),
            },
            Arc::new(ChainBlocks(chain.clone())),
        )
        .await
        .unwrap();
        boot.push(addr_of(&net).await);
        let pool =
            Arc::new(TxPool::new(bolt_txpool::PoolConfig::new(1337, 30_000_000, 10_000_000)));
        let v = Validator {
            chain: chain.clone(),
            pool: pool.clone(),
            net: net.clone(),
            keys: keys.into_iter().map(dev_key).collect(),
            cfg: ValidatorConfig {
                slot_ms: 1000,
                base_timeout_ms: 3000,
                state_dir: dir.path().join("consensus"),
            },
            miner: None,
        };
        let task = tokio::spawn(async move {
            let _ = v.run(events).await;
        });
        nodes.push((chain, pool, net, task));
        dirs.push(dir);
    }
    // Wait for the chain to run (the mesh is up once blocks flow).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while nodes.iter().any(|n| n.0.head().unwrap().number < 2) {
        assert!(tokio::time::Instant::now() < deadline, "no blocks");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Nonce 1 leaves a gap, so it stays pooled and can only reach B by gossip.
    let raw = tx(1).encoded_2718();
    {
        let r = nodes[0].0.store().reader().unwrap();
        nodes[0].1.add_raw(&raw, &HeadState(&r)).unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while nodes[1].1.is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "transaction not gossiped");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Nonce 0 is then included by whichever node produces the next block, and both drop it.
    let raw0 = tx(0).encoded_2718();
    {
        let r = nodes[1].0.store().reader().unwrap();
        nodes[1].1.add_raw(&raw0, &HeadState(&r)).unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let r = nodes[0].0.store().reader().unwrap();
        let nonce = bolt_txpool::AccountState::nonce_balance(
            &HeadState(&r),
            &"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".parse().unwrap(),
        )
        .0;
        if nonce == 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "both transactions not included (nonce {nonce})"
        );
        drop(r);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    for (_, _, net, task) in nodes {
        task.abort();
        net.shutdown().await;
    }
}
