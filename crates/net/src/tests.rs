use super::*;
use parking_lot::RwLock;
use std::collections::HashMap;

#[derive(Default)]
struct Mem(RwLock<HashMap<Cid, Vec<u8>>>);
impl BlockSource for Mem {
    fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.0.read().get(cid).cloned()
    }
}

fn local() -> Vec<Multiaddr> {
    vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()]
}

async fn node(
    producer: Option<PeerId>,
    bootnodes: Vec<Multiaddr>,
    key: identity::Keypair,
) -> (NetHandle, mpsc::Receiver<NetEvent>, Arc<Mem>) {
    node_with_fork(producer, bootnodes, key, "aabbccdd-0").await
}

async fn node_with_fork(
    producer: Option<PeerId>,
    bootnodes: Vec<Multiaddr>,
    key: identity::Keypair,
    fork: &str,
) -> (NetHandle, mpsc::Receiver<NetEvent>, Arc<Mem>) {
    let mem = Arc::new(Mem::default());
    let mine = fork.to_string();
    let check = ForkCheck(Arc::new(move |r: &str| {
        if r == mine { PeerRules::Compatible } else { PeerRules::Incompatible }
    }));
    let (h, rx) = start(
        NetConfig {
            chain_id: 1337,
            keypair: key,
            listen: local(),
            bootnodes,
            producer,
            fork_id: fork.to_string(),
            fork_check: Some(check),
            relay_server: false,
            agent: String::new(),
        },
        mem.clone(),
    )
    .await
    .unwrap();
    (h, rx, mem)
}

#[tokio::test(flavor = "multi_thread")]
async fn peers_on_other_rules_are_dropped() {
    let (a, _a_rx, _) =
        node_with_fork(None, vec![], identity::Keypair::generate_ed25519(), "aabbccdd-0").await;
    let a_addrs = addrs(&a).await;
    let (same, _s_rx, _) =
        node_with_fork(None, a_addrs.clone(), identity::Keypair::generate_ed25519(), "aabbccdd-0")
            .await;
    let (other, _o_rx, _) =
        node_with_fork(None, a_addrs, identity::Keypair::generate_ed25519(), "11223344-0").await;
    let mut ok = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let peers = a.peers().await;
        if peers.contains(&same.peer_id()) && !peers.contains(&other.peer_id()) {
            ok = true;
            // stays disconnected
            tokio::time::sleep(Duration::from_millis(500)).await;
            if a.peers().await.contains(&other.peer_id()) {
                ok = false;
                continue;
            }
            break;
        }
    }
    assert!(ok, "compatible peer kept, incompatible dropped");
}

async fn addrs(h: &NetHandle) -> Vec<Multiaddr> {
    for _ in 0..50 {
        let a = h.listen_addrs().await;
        if !a.is_empty() {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no listen address");
}

#[tokio::test(flavor = "multi_thread")]
async fn announce_fetch_and_forward() {
    let ka = identity::Keypair::generate_ed25519();
    let a_id = ka.public().to_peer_id();
    let (a, mut a_rx, a_mem) = node(None, vec![], ka).await;
    let (b, mut b_rx, _b_mem) =
        node(Some(a_id), addrs(&a).await, identity::Keypair::generate_ed25519()).await;

    // A holds two blocks, one of them larger than a gossip message.
    let small = b"small block".to_vec();
    let big = vec![7u8; 900 * 1024];
    let (c1, c2) = (
        bolt_ipld::sha256_cid(bolt_ipld::RAW, &small),
        bolt_ipld::sha256_cid(bolt_ipld::RAW, &big),
    );
    a_mem.0.write().insert(c1, small.clone());
    a_mem.0.write().insert(c2, big.clone());

    // Wait until the gossipsub mesh has B subscribed, then announce.
    let ann = Announce {
        height: 1,
        root: c1,
        envelope: vec![1],
        header: vec![2],
        inline: vec![],
        proof: vec![],
        at: 0,
    };
    let got = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            a.publish(ann.clone()).await.unwrap();
            if let Ok(Some(ev)) =
                tokio::time::timeout(Duration::from_millis(500), b_rx.recv()).await
                && let NetEvent::Announce { via, announce } = ev
            {
                return (via, announce);
            }
        }
    })
    .await
    .expect("announcement delivered");
    assert_eq!(got.0, a_id);
    assert!(got.1.at > 0, "the network stamps the publication time");
    assert_eq!(Announce { at: 0, ..got.1 }, ann);

    // B fetches both blocks from A over bitswap.
    let t = std::time::Instant::now();
    let blocks = b.fetch(&[c1, c2], &[a_id]).await.unwrap();
    println!("fetched {} KiB in {:?}", (small.len() + big.len()) / 1024, t.elapsed());
    for i in 0..3u8 {
        let d = vec![i; 190 * 1024];
        let c = bolt_ipld::sha256_cid(bolt_ipld::RAW, &d);
        a_mem.0.write().insert(c, d);
        let t = std::time::Instant::now();
        b.fetch(&[c], &[a_id]).await.unwrap();
        println!("fetched 190 KiB in {:?}", t.elapsed());
        let d = vec![i + 10; 10];
        let c = bolt_ipld::sha256_cid(bolt_ipld::RAW, &d);
        a_mem.0.write().insert(c, d);
        let t = std::time::Instant::now();
        b.fetch(&[c], &[a_id]).await.unwrap();
        println!("fetched 10 B in {:?}", t.elapsed());
    }
    assert_eq!(blocks[&c1], small);
    assert_eq!(blocks[&c2], big);

    // Unknown blocks time out instead of hanging.
    let missing = bolt_ipld::sha256_cid(bolt_ipld::RAW, b"nobody has this");
    assert!(b.fetch(&[missing], &[a_id]).await.is_err());

    // B forwards a transaction to A; A answers.
    let fwd = tokio::spawn({
        let b = b.clone();
        async move { b.forward_tx(a_id, vec![0xde, 0xad]).await }
    });
    loop {
        match a_rx.recv().await.unwrap() {
            NetEvent::Tx { raw, reply } => {
                assert_eq!(raw, vec![0xde, 0xad]);
                reply.send(Ok(B256::repeat_byte(9))).unwrap();
                break;
            }
            _ => continue,
        }
    }
    assert_eq!(fwd.await.unwrap(), Ok(B256::repeat_byte(9)));
}

#[tokio::test(flavor = "multi_thread")]
async fn announcements_from_other_authors_are_dropped() {
    let producer = identity::Keypair::generate_ed25519().public().to_peer_id();
    let (a, _a_rx, _) = node(None, vec![], identity::Keypair::generate_ed25519()).await;
    let (_b, mut b_rx, _) =
        node(Some(producer), addrs(&a).await, identity::Keypair::generate_ed25519()).await;
    let ann = Announce {
        height: 1,
        root: bolt_ipld::sha256_cid(bolt_ipld::RAW, b"x"),
        envelope: vec![],
        header: vec![],
        inline: vec![],
        proof: vec![],
        at: 0,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        a.publish(ann.clone()).await.unwrap();
        if let Ok(Some(NetEvent::Announce { .. })) =
            tokio::time::timeout(Duration::from_millis(300), b_rx.recv()).await
        {
            panic!("announcement from a non-producer must be rejected");
        }
    }
}

#[test]
fn mainnet_bootnodes_are_dnsaddr() {
    let b = mainnet_bootnodes();
    assert_eq!(b.len(), 9);
    assert_eq!(b[0].to_string(), "/dnsaddr/node001.cafeca.io");
    assert_eq!(b[8].to_string(), "/dnsaddr/node009.cafeca.io");
}

/// A node with no listen address of its own (as if behind NAT) becomes reachable through a relay
/// and serves blocks over the relayed connection.
#[tokio::test(flavor = "multi_thread")]
async fn relayed_node_serves_blocks() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
    let tcp_local = || vec!["/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap()];
    let start_node = |listen: Vec<Multiaddr>, boot: Vec<Multiaddr>, relay_server: bool| async move {
        let mem = Arc::new(Mem::default());
        let (h, rx) = start(
            NetConfig {
                chain_id: 1337,
                keypair: identity::Keypair::generate_ed25519(),
                listen,
                bootnodes: boot,
                producer: None,
                fork_id: "aabbccdd-0".into(),
                fork_check: None,
                relay_server,
                agent: String::new(),
            },
            mem.clone(),
        )
        .await
        .unwrap();
        (h, rx, mem)
    };
    let (relay, _r_rx, _) = start_node(tcp_local(), vec![], true).await;
    let relay_addr = loop {
        if let Some(a) =
            relay.listen_addrs().await.into_iter().find(|a| a.to_string().contains("/tcp/"))
        {
            break a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // B listens nowhere except through the relay.
    let (b, _b_rx, b_mem) = start_node(vec![], vec![relay_addr.clone()], false).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    b.listen(relay_addr.clone().with(Protocol::P2pCircuit)).await.unwrap();
    let data = b"block served through a relay".to_vec();
    let cid = bolt_ipld::sha256_cid(bolt_ipld::RAW, &data);
    b_mem.0.write().insert(cid, data.clone());
    let circuit = relay_addr.clone().with(Protocol::P2pCircuit).with(Protocol::P2p(b.peer_id()));
    // C dials B only through the relay, then fetches the block from it.
    let (c, _c_rx, _) = start_node(tcp_local(), vec![], false).await;
    let mut got = None;
    for _ in 0..50 {
        let _ = c.dial(circuit.clone()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        if c.peers().await.contains(&b.peer_id())
            && let Ok(m) = c.fetch(&[cid], &[b.peer_id()]).await
        {
            got = m.get(&cid).cloned();
            break;
        }
    }
    assert_eq!(got, Some(data), "block fetched over the relayed connection");
}

/// TCP sockets of this process that are ESTABLISHED (from /proc/net/tcp*).
fn established_tcp() -> usize {
    let mut inodes = std::collections::HashSet::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for line in std::fs::read_to_string(f).unwrap_or_default().lines().skip(1) {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() > 9 && c[3] == "01" {
                inodes.insert(c[9].to_string());
            }
        }
    }
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter_map(|l| {
            l.to_str()?.strip_prefix("socket:[")?.strip_suffix(']').map(|s| s.to_string())
        })
        .filter(|i| inodes.contains(i))
        .count()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "takes 5 minutes; run with --ignored"]
async fn connections_do_not_accumulate() {
    let mut nodes = Vec::new();
    let mut boot: Vec<Multiaddr> = Vec::new();
    for i in 0..4 {
        let key = identity::Keypair::generate_ed25519();
        let (h, mut rx) = start(
            NetConfig {
                chain_id: 1337,
                keypair: key,
                listen: vec![
                    "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                    "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ],
                bootnodes: boot.clone(),
                producer: None,
                fork_id: "aabbccdd-0".into(),
                fork_check: None,
                relay_server: i == 0,
                agent: String::new(),
            },
            Arc::new(Mem::default()),
        )
        .await
        .unwrap();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        if i == 0 {
            boot = addrs(&h).await;
        }
        nodes.push(h);
    }
    // AutoNAT probes every 60 s until each node knows it is reachable; every probe used to leave
    // an extra connection open for good (8 more sockets a minute here, about 1,000 open files
    // per testnet node after a week).
    let mut counts = Vec::new();
    for t in 0..10 {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let n = established_tcp();
        eprintln!("t={}s established tcp sockets: {n}", (t + 1) * 30);
        counts.push(n);
    }
    // 4 nodes, at most one connection per pair (2 sockets each in this process).
    let last = *counts.last().unwrap();
    assert!(last <= 12, "connections accumulate: {counts:?}");
}

/// The census: A–B–C in a line; A learns C (not connected) from C's heartbeat, with versions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nodes_learn_each_other_from_heartbeats() {
    let start_node = |boot: Vec<Multiaddr>, agent: &str| {
        let agent = agent.to_string();
        async move {
            start(
                NetConfig {
                    chain_id: 1337,
                    keypair: identity::Keypair::generate_ed25519(),
                    listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                    bootnodes: boot,
                    producer: None,
                    fork_id: "aabbccdd-0".into(),
                    fork_check: None,
                    relay_server: false,
                    agent,
                },
                Arc::new(Mem::default()),
            )
            .await
            .unwrap()
        }
    };
    let addr = |h: NetHandle| async move {
        loop {
            if let Some(a) = h.listen_addrs().await.into_iter().next() {
                return a;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let (a, _ra) = start_node(vec![], "boltchain/v9-a").await;
    let (b, _rb) = start_node(vec![addr(a.clone()).await], "boltchain/v9-b").await;
    let (c, _rc) = start_node(vec![addr(b.clone()).await], "boltchain/v9-c").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let n = a.nodes();
        let v = |p: PeerId| n.iter().find(|r| r.peer == p).map(|r| r.version.clone());
        if v(a.peer_id()).as_deref() == Some("boltchain/v9-a")
            && v(b.peer_id()).as_deref() == Some("boltchain/v9-b")
            && v(c.peer_id()).as_deref() == Some("boltchain/v9-c")
        {
            assert!(n.iter().find(|r| r.peer == b.peer_id()).unwrap().direct);
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "census incomplete: {n:?}");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
