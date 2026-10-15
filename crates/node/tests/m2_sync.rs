//! M2 acceptance: one producer and five followers on localhost. Followers receive blocks only
//! through IPFS (gossipsub announcements + Bitswap). Three followers are not even connected to the
//! producer; they learn about blocks from other followers and fetch the data from whoever has it.
//! A sixth follower joins late and backfills by walking parent envelopes.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use bolt_chain::Chain;
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_primitives::Genesis;
use bolt_sync::{ChainBlocks, Follower, Outcome};
use libp2p::{Multiaddr, PeerId, identity};
use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};

const DEV_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn genesis() -> Genesis {
    Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap()
}

async fn start_net(
    chain: Arc<Chain>,
    producer: Option<PeerId>,
    boot: Vec<Multiaddr>,
) -> (NetHandle, tokio::sync::mpsc::Receiver<NetEvent>) {
    bolt_net::start(
        NetConfig {
            chain_id: chain.config().chain_id,
            keypair: identity::Keypair::generate_ed25519(),
            listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            bootnodes: boot,
            producer,
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

struct FollowerNode {
    chain: Arc<Chain>,
    _dir: tempfile::TempDir,
    fetch_ms: Arc<Mutex<Vec<u64>>>,
    net: NetHandle,
}

async fn follower(producer: PeerId, boot: Vec<Multiaddr>) -> FollowerNode {
    let dir = tempfile::tempdir().unwrap();
    let chain = Arc::new(Chain::open(dir.path(), &genesis()).unwrap());
    let (net, mut events) = start_net(chain.clone(), Some(producer), boot).await;
    let fetch_ms = Arc::new(Mutex::new(Vec::new()));
    let f = Follower::new(chain.clone(), net.clone());
    let log = fetch_ms.clone();
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if let NetEvent::Announce { via, announce } = ev {
                match f.on_announce(via, announce).await {
                    Ok(Outcome::Imported { fetch_ms, count, .. }) => {
                        if count == 1 {
                            log.lock().push(fetch_ms);
                        }
                    }
                    Ok(Outcome::Known) => {}
                    Err(e) => eprintln!("follower: {e}"),
                }
            }
        }
    });
    FollowerNode { chain, _dir: dir, fetch_ms, net }
}

fn txs(
    key: &PrivateKeySigner,
    nonce: &mut u64,
    n: usize,
    calldata: usize,
    zeros: bool,
) -> Vec<(TxEnvelope, Address)> {
    (0..n)
        .map(|_| {
            let input: Bytes =
                if zeros { vec![0u8; calldata].into() } else { vec![0x5a; calldata].into() };
            let mut t = TxEip1559 {
                chain_id: 1337,
                nonce: *nonce,
                gas_limit: 2_000_000,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 1,
                to: TxKind::Call(Address::repeat_byte(0x42)),
                value: U256::from(1),
                input,
                ..Default::default()
            };
            *nonce += 1;
            let sig = key.sign_transaction_sync(&mut t).unwrap();
            (t.into_signed(sig).into(), key.address())
        })
        .collect()
}

async fn wait_all(nodes: &[&FollowerNode], height: u64, secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let heads: Vec<u64> = nodes.iter().map(|n| n.chain.head().unwrap().number).collect();
        if heads.iter().all(|h| *h >= height) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "followers stuck at {heads:?}, want {height}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_followers_sync_only_over_ipfs() {
    let pdir = tempfile::tempdir().unwrap();
    let producer = Arc::new(Chain::open(pdir.path(), &genesis()).unwrap());
    let (pnet, _pev) = start_net(producer.clone(), None, vec![]).await;
    let pid = pnet.peer_id();
    let paddr = addr_of(&pnet).await;

    // f1, f2 dial the producer; f3–f5 only know f1.
    let f1 = follower(pid, vec![paddr.clone()]).await;
    let f2 = follower(pid, vec![paddr.clone()]).await;
    let f1addr = addr_of(&f1.net).await;
    let f3 = follower(pid, vec![f1addr.clone()]).await;
    let f4 = follower(pid, vec![f1addr.clone()]).await;
    let f5 = follower(pid, vec![f1addr.clone()]).await;
    let all = [&f1, &f2, &f3, &f4, &f5];
    // Let connections and gossipsub meshes form.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let key: PrivateKeySigner = DEV_KEY.parse().unwrap();
    let mut nonce = 0u64;
    let mut sizes = Vec::new();
    for i in 1..=24u64 {
        let batch = match i % 4 {
            0 => txs(&key, &mut nonce, 60, 3_000, false), // ~190 KB body: fetched over bitswap
            1 => txs(&key, &mut nonce, 5, 100, false),    // small: inlined in the announcement
            2 => txs(&key, &mut nonce, 14, 100_000, true), // ~1.4 MB body: two chunks
            _ => vec![],                                  // empty block
        };
        let producer2 = producer.clone();
        let built = tokio::task::spawn_blocking(move || {
            producer2.build_block(batch, 1_000 + i * 6, Address::ZERO)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(built.rejected.is_empty(), "{:?}", built.rejected);
        sizes.push((i, built.bundle.body_len(), built.bundle.envelope.chunks.len()));
        bolt_sync::publish(&pnet, &built).await.unwrap();
        wait_all(&all, i, 15).await;
    }

    // Every follower has exactly the producer's chain and blockstore roots.
    let head = producer.head().unwrap();
    let proot = producer.store().reader().unwrap().envelope_root(head.number).unwrap();
    for f in all {
        assert_eq!(f.chain.head().unwrap(), head);
        assert_eq!(f.chain.store().reader().unwrap().envelope_root(head.number).unwrap(), proot);
    }

    // Latency from announcement to having all data in hand.
    for (i, f) in all.iter().enumerate() {
        let v = f.fetch_ms.lock().clone();
        println!("f{} ({}): {:?}", i + 1, if i < 2 { "direct" } else { "via f1" }, v);
    }
    let mut ms: Vec<u64> = all.iter().flat_map(|f| f.fetch_ms.lock().clone()).collect();
    ms.sort_unstable();
    let p95 = ms[(ms.len() * 95 / 100).min(ms.len() - 1)];
    let p50 = ms[ms.len() / 2];
    println!("block bodies (height, bytes, chunks): {sizes:?}");
    println!(
        "announce -> data in hand over {} imports: p50 {p50} ms, p95 {p95} ms, max {} ms",
        ms.len(),
        ms.last().unwrap()
    );
    assert!(p95 < 1000, "p95 {p95} ms exceeds the 1 s target");

    // A late joiner that only knows f5 backfills by walking parent envelopes.
    let late = follower(pid, vec![addr_of(&f5.net).await]).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let producer2 = producer.clone();
    let batch = txs(&key, &mut nonce, 3, 10, false);
    let built =
        tokio::task::spawn_blocking(move || producer2.build_block(batch, 5_000, Address::ZERO))
            .await
            .unwrap()
            .unwrap();
    bolt_sync::publish(&pnet, &built).await.unwrap();
    wait_all(&[&late, &f1, &f5], 25, 30).await;
    assert_eq!(late.chain.head().unwrap(), producer.head().unwrap());
    println!("late joiner backfilled 25 blocks via parent links");
}
