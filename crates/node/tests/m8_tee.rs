//! ADR 0013 from the command line, on a dev PoS chain (7 genesis validators on 3 nodes) whose
//! genesis trusts the simulated attestation PKI:
//!
//! - the simulated Intel collateral is submitted, an image registered with its measurements;
//! - a TDX operator registers a simulated machine (its quote verified on chain), bonds, and an
//!   agent lease is activated through the relay (the operator holds no BOLT for it); the renter
//!   verifies the enclave locally and hands it a secret; checkpoints arrive by the relay;
//! - restarting the runtime from an old state cannot roll the lease back;
//! - the operator leaves, the lease migrates to another machine and continues its versions;
//! - two states signed for one version slash the second operator and blacklist its machine;
//! - a T2 (TPM) machine is verified by the panel (evidence, event log, credential challenge),
//!   and so is its enclave's activation;
//! - the renter's account delegates to the limited wallet and the enclave key spends within it.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_chain::Chain;
use bolt_net::{NetConfig, NetEvent, NetHandle};
use bolt_primitives::{
    Genesis,
    bls::{BlsSecretKey, dev_eth_key, dev_key},
    genesis::GenesisAccount,
};
use bolt_store::StateView;
use bolt_sync::ChainBlocks;
use bolt_system::{abi::*, addresses::*, queries};
use bolt_txpool::TxPool;
use boltchain::{
    storage::{Storage, StorageConfig},
    validator::{Validator, ValidatorConfig},
};
use libp2p::{Multiaddr, identity};
use std::{path::Path, process::Child, sync::Arc, time::Duration};

const EPOCH: u64 = 6;

fn owner(i: u32) -> PrivateKeySigner {
    PrivateKeySigner::from_slice(&dev_eth_key(i)).unwrap()
}

fn funded() -> PrivateKeySigner {
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse().unwrap()
}

fn genesis(accounts: &[Address]) -> Genesis {
    let mut g = Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap();
    g.config.epoch_slots = EPOCH;
    g.config.committee_size = 16;
    g.config.history_recent_epochs = Some(1);
    for i in 0..7 {
        g.alloc.insert(
            owner(i).address(),
            GenesisAccount { balance: U256::from(10u128.pow(19)), ..Default::default() },
        );
    }
    for a in accounts {
        g.alloc.insert(
            *a,
            GenesisAccount { balance: U256::from(10u128.pow(21)), ..Default::default() },
        );
    }
    g
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

fn wallet_file(dir: &Path, name: &str, s: &PrivateKeySigner) -> String {
    let p = dir.join(format!("{name}.json"));
    let j = serde_json::json!({"address": s.address(), "privateKey": format!("0x{}", alloy_primitives::hex::encode(s.to_bytes()))});
    std::fs::write(&p, j.to_string()).unwrap();
    p.display().to_string()
}

fn cli(args: &[&str]) -> String {
    let out =
        std::process::Command::new(env!("CARGO_BIN_EXE_boltchain")).args(args).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    eprintln!("$ boltchain {}\n{stdout}{}", args.join(" "), String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "boltchain {} failed:\n{stdout}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn cli_fails(args: &[&str]) -> String {
    let out =
        std::process::Command::new(env!("CARGO_BIN_EXE_boltchain")).args(args).output().unwrap();
    assert!(!out.status.success(), "boltchain {} should have failed", args.join(" "));
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Runtime {
    child: Child,
    url: String,
    state: std::path::PathBuf,
    args: Vec<String>,
}

impl Runtime {
    fn start(kind: &str, seed: &str, rpc: &str, relay: &str, state: &Path) -> Self {
        let port = free_port();
        let args: Vec<String> = [
            "enclave",
            "runtime",
            "--simulate",
            "--kind",
            kind,
            "--seed",
            seed,
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--state",
            &state.display().to_string(),
            "--checkpoint-every",
            "3",
            "--relay",
            relay,
            "--rpc",
            rpc,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_boltchain"))
            .args(&args)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let url = format!("http://127.0.0.1:{port}");
        for _ in 0..100 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Self { child, url, state: state.to_path_buf(), args }
    }

    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = std::process::Command::new(env!("CARGO_BIN_EXE_boltchain"))
            .args(&self.args)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(800));
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// The enclave key the runtime holds for `lease` (it never leaves a real enclave).
    fn key(&self, lease: u64) -> PrivateKeySigner {
        let st: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.state.join("runtime.json")).unwrap())
                .unwrap();
        let k = st["leases"][lease.to_string()]["key"].as_str().unwrap();
        PrivateKeySigner::from_slice(&alloy_primitives::hex::decode(k).unwrap()).unwrap()
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_lease_attested_enclaves() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
    let admin = funded();
    let (op1, op2, op3, renter) = (
        PrivateKeySigner::random(),
        PrivateKeySigner::random(),
        PrivateKeySigner::random(),
        PrivateKeySigner::random(),
    );
    let g = genesis(&[op2.address(), op3.address(), renter.address()]);
    let key_sets: Vec<Vec<u32>> = vec![vec![0, 3, 6], vec![1, 4], vec![2, 5]];
    let mut chains = Vec::new();
    let mut boot: Vec<Multiaddr> = Vec::new();
    let mut rpcs = Vec::new();
    let mut keep = Vec::new();
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
        let port = free_port();
        let rpc_url = format!("http://127.0.0.1:{port}");
        let storage = Storage::new(
            chain.clone(),
            net.clone(),
            StorageConfig {
                keys: keys.clone(),
                // Dev chains trust the simulated TPM vendor.
                tpm_roots: boltchain::attest::tpm_roots(None, true).unwrap(),
                ..Default::default()
            },
        );
        let s = tokio::spawn(storage.clone().run(srx));
        let relay = rpcs.is_empty().then(|| {
            Arc::new(boltchain::relay::Relay::new(
                rpc_url.clone(),
                owner(0),
                U256::from(10u128.pow(15)),
            )) as Arc<dyn bolt_rpc::CallRelay>
        });
        let ctx = bolt_rpc::RpcContext {
            chain: chain.clone(),
            pool: pool.clone(),
            client_version: "test".into(),
            forwarder: None,
            host: None,
            relay,
        };
        let (_, handle) =
            bolt_rpc::start(format!("127.0.0.1:{port}").parse().unwrap(), ctx).await.unwrap();
        rpcs.push(rpc_url);
        let v = Validator {
            chain: chain.clone(),
            pool,
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
        chains.push(chain);
        keep.push((dir, net, storage, s, t, handle));
    }
    let c0 = chains[0].clone();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while c0.head().unwrap().number < 2 {
        assert!(tokio::time::Instant::now() < deadline, "no blocks");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let rpc0 = rpcs[0].clone();
    let rpc1 = rpcs[1].clone();
    let chain = c0.clone();
    tokio::task::spawn_blocking(move || {
        let tmp = tempfile::tempdir().unwrap();
        let w_admin = wallet_file(tmp.path(), "admin", &admin);
        let w_op1 = wallet_file(tmp.path(), "op1", &op1);
        let w_op2 = wallet_file(tmp.path(), "op2", &op2);
        let w_op3 = wallet_file(tmp.path(), "op3", &op3);
        let w_renter = wallet_file(tmp.path(), "renter", &renter);
        let r = rpc1.as_str();

        // Collateral and the image.
        let out = cli(&["collateral", "update", "--simulated", "--wallet", &w_admin, "--rpc", r]);
        assert!(out.contains("document(s) submitted"), "{out}");
        eprintln!("{out}");
        assert!(
            cli(&["collateral", "show", "--fmspc", "00906ED50000", "--rpc", r])
                .contains("evaluation 1")
        );
        cli(&[
            "image", "register", "--wallet", &w_renter, "--name", "bolt-art", "--source",
            "bafy-src", "--rpc", r,
        ]);
        cli(&[
            "image",
            "measure",
            "--wallet",
            &w_renter,
            "--image",
            "1",
            "--kind",
            "tdx",
            "--simulate",
            "--rpc",
            r,
        ]);
        cli(&[
            "image",
            "measure",
            "--wallet",
            &w_renter,
            "--image",
            "1",
            "--kind",
            "tpm",
            "--simulate",
            "--rpc",
            r,
        ]);
        assert!(cli(&["image", "list", "--rpc", r]).contains("TPM (T2)"));

        // A TDX operator: its gas comes from a small transfer; its runtime submits via the relay.
        boltchain::wallet::send_tx(
            r,
            &admin,
            op1.address(),
            U256::from(10u128.pow(20)),
            Default::default(),
        )
        .unwrap();
        let a_state = tmp.path().join("runtime-a");
        let mut rt_a = Runtime::start("tdx", "machine-a", r, &rpc0, &a_state);
        let out = cli(&[
            "enclave",
            "register",
            "--wallet",
            &w_op1,
            "--runtime",
            &rt_a.url,
            "--price",
            "1",
            "--rpc",
            r,
        ]);
        assert!(out.contains("machine 1 registered and verified"), "{out}");
        cli(&["enclave", "bond", "--wallet", &w_op1, "deposit", "64", "--rpc", r]);
        assert!(cli(&["lease", "offers", "--rpc", r]).contains("machine 1: TDX (T1)"));

        // The lease: escrow, activation through the relay, local verification, a secret.
        let agent = B256::repeat_byte(0xa9).to_string();
        let out = cli(&[
            "lease",
            "create",
            "--wallet",
            &w_renter,
            "--machine",
            "1",
            "--image",
            "1",
            "--agent",
            &agent,
            "--hours",
            "10",
            "--min-bond",
            "32",
            "--rpc",
            r,
        ]);
        assert!(out.contains("lease 1 created"), "{out}");
        let out = cli(&[
            "enclave",
            "activate",
            "--lease",
            "1",
            "--runtime",
            &rt_a.url,
            "--relay",
            &rpc0,
            "--rpc",
            r,
        ]);
        assert!(out.contains("lease 1: active"), "{out}");
        let out = cli(&["lease", "verify", "1", "--simulated", "--rpc", r]);
        assert!(out.contains("safe to deliver secrets"), "{out}");
        let secret = tmp.path().join("secret.txt");
        std::fs::write(&secret, b"sk-live-api-key-for-the-agent").unwrap();
        let out =
            cli(&["lease", "deliver", "1", "--file", &secret.display().to_string(), "--rpc", r]);
        assert!(out.contains("secret delivered"), "{out}");

        // Checkpoints arrive through the relay.
        let version = |c: &Chain, id: u64| {
            view(c, LEASES, IEnclaveLease::leaseCall { id: U256::from(id) }).version
        };
        wait("checkpoints", 60, || version(&chain, 1) >= 2);
        let snapshot = std::fs::read(a_state.join("runtime.json")).unwrap();
        wait("more checkpoints", 60, || version(&chain, 1) >= 4);

        // Restarting from an old state cannot go back: its checkpoints are refused.
        let before = version(&chain, 1);
        rt_a.stop();
        std::fs::write(a_state.join("runtime.json"), &snapshot).unwrap();
        rt_a.restart();
        std::thread::sleep(Duration::from_secs(8));
        let after = version(&chain, 1);
        assert!(after >= before, "rolled back from {before} to {after}");
        rt_a.stop();
        let after_stop = version(&chain, 1);

        // The operator leaves; the renter moves the lease to another machine.
        let b_state = tmp.path().join("runtime-b");
        let rt_b = Runtime::start("tdx", "machine-b", r, &rpc0, &b_state);
        assert!(
            cli(&[
                "enclave",
                "register",
                "--wallet",
                &w_op3,
                "--runtime",
                &rt_b.url,
                "--price",
                "1",
                "--rpc",
                r
            ])
            .contains("machine 2 registered")
        );
        cli(&["enclave", "bond", "--wallet", &w_op3, "deposit", "40", "--rpc", r]);
        cli_fails(&["lease", "migrate", "--wallet", &w_renter, "1", "--to", "2", "--rpc", r]);
        cli(&["enclave", "exit", "--wallet", &w_op1, "--lease", "1", "--rpc", r]);
        cli(&["lease", "migrate", "--wallet", &w_renter, "1", "--to", "2", "--rpc", r]);
        let old_key = rt_a.key(1);
        cli(&[
            "enclave",
            "activate",
            "--lease",
            "1",
            "--runtime",
            &rt_b.url,
            "--relay",
            &rpc0,
            "--rpc",
            r,
        ]);
        let l = view(&chain, LEASES, IEnclaveLease::leaseCall { id: U256::from(1) });
        assert_eq!(l.machine, 2);
        assert_ne!(l.signer, old_key.address());
        wait("checkpoints on the new machine", 60, || version(&chain, 1) > after_stop);
        assert!(
            cli(&["lease", "verify", "1", "--simulated", "--rpc", r]).contains("safe to deliver")
        );

        // Equivocation: two states for one version, both signed by machine 2's enclave key.
        let key_b = rt_b.key(1);
        let v = version(&chain, 1) + 50;
        let signed = |root: B256| {
            let cid = keccak256(root);
            let bh = B256::repeat_byte(7);
            let d = view(
                &chain,
                LEASES,
                IEnclaveLease::checkpointDigestCall {
                    id: U256::from(1),
                    version: v,
                    stateRoot: root,
                    cidHash: cid,
                    seenBlockhash: bh,
                },
            );
            IEnclaveLease::Signed {
                stateRoot: root,
                cidHash: cid,
                seenBlockhash: bh,
                sig: key_b.sign_hash_sync(&d).unwrap().as_bytes().to_vec().into(),
            }
        };
        let data = IEnclaveLease::reportEquivocationCall {
            id: U256::from(1),
            version: v,
            a: signed(B256::repeat_byte(1)),
            b: signed(B256::repeat_byte(2)),
        }
        .abi_encode();
        boltchain::wallet::send_tx(r, &admin, LEASES, U256::ZERO, data.into()).unwrap();
        let mid = view(&chain, LEASES, IEnclaveLease::machineCall { m: 2 }).machineId;
        assert!(view(&chain, LEASES, IEnclaveLease::blacklistedCall { machineId: mid }));
        assert_eq!(
            view(&chain, LEASES, IEnclaveLease::operatorsCall { operator: op3.address() }).bond,
            U256::ZERO
        );
        assert_eq!(
            view(&chain, LEASES, IEnclaveLease::balanceOfCall { account: admin.address() }),
            U256::from(20u128 * 10u128.pow(18))
        );
        assert_eq!(view(&chain, LEASES, IEnclaveLease::leaseCall { id: U256::from(1) }).state, 4);
        drop(rt_b);

        // A T2 machine: the verifier panel appraises its evidence and challenges its TPM.
        let c_state = tmp.path().join("runtime-c");
        let rt_c = Runtime::start("tpm", "t2-machine", r, &rpc0, &c_state);
        let out = cli(&[
            "enclave",
            "register",
            "--wallet",
            &w_op2,
            "--runtime",
            &rt_c.url,
            "--price",
            "0.5",
            "--gpu",
            "GB10",
            "--rpc",
            r,
        ]);
        assert!(out.contains("machine 3 registered; the verifier panel"), "{out}");
        wait("the panel to verify the T2 machine", 120, || {
            view(&chain, LEASES, IEnclaveLease::machineCall { m: 3 }).verified
        });
        cli(&[
            "lease",
            "create",
            "--wallet",
            &w_renter,
            "--machine",
            "3",
            "--image",
            "1",
            "--agent",
            &agent,
            "--hours",
            "4",
            "--rpc",
            r,
        ]);
        cli(&[
            "enclave",
            "activate",
            "--lease",
            "2",
            "--runtime",
            &rt_c.url,
            "--wallet",
            &w_op2,
            "--rpc",
            r,
        ]);
        wait("the panel to activate the T2 lease", 120, || {
            view(&chain, LEASES, IEnclaveLease::leaseCall { id: U256::from(2) }).state == 3
        });
        assert!(
            cli(&["lease", "verify", "2", "--simulated", "--rpc", r]).contains("safe to deliver")
        );
        wait("T2 checkpoints", 60, || version(&chain, 2) >= 1);

        // The renter's account delegates to the limited wallet; the enclave key spends in it.
        let shop = Address::repeat_byte(0x5b);
        cli(&[
            "lease",
            "wallet",
            "--wallet",
            &w_renter,
            "--lease",
            "2",
            "--daily",
            "1",
            "--per-tx",
            "0.5",
            "--target",
            &shop.to_string(),
            "--rpc",
            r,
        ]);
        wait("the delegation on this node", 30, || {
            let r = chain.store().reader().unwrap();
            queries::call(
                &StateView::latest(&r),
                1337,
                renter.address(),
                ILimitedWallet::configCall {},
            )
            .is_ok_and(|c| c.lease == U256::from(2))
        });
        let key_c = rt_c.key(2);
        let pay = |value: u128| -> bool {
            let calls = vec![ILimitedWallet::Call {
                to: shop,
                value: U256::from(value),
                data: Default::default(),
            }];
            let cfg = view(&chain, renter.address(), ILimitedWallet::configCall {});
            let deadline = U256::from(u64::MAX);
            let d = view(
                &chain,
                renter.address(),
                ILimitedWallet::executeDigestCall {
                    calls: calls.clone(),
                    nonce: cfg.nonce,
                    deadline,
                },
            );
            let sig = key_c.sign_hash_sync(&d).unwrap();
            let data = ILimitedWallet::executeSignedCall {
                calls,
                deadline,
                sig: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();
            let ok =
                boltchain::wallet::send_tx(r, &admin, renter.address(), U256::ZERO, data.into())
                    .is_ok();
            // Let this node catch up with the node the transaction went to.
            std::thread::sleep(Duration::from_secs(2));
            ok
        };
        let milli = 10u128.pow(15);
        assert!(pay(400 * milli));
        assert!(!pay(600 * milli), "over the per-transaction limit");
        assert!(pay(400 * milli));
        assert!(!pay(400 * milli), "over the daily limit");
        let bal = boltchain::wallet::rpc(r, "eth_getBalance", serde_json::json!([shop, "latest"]))
            .unwrap();
        assert_eq!(bal.as_str().unwrap(), format!("0x{:x}", 800 * milli));
        drop(rt_c);
    })
    .await
    .unwrap();
    for (_, _, _, s, t, h) in keep {
        s.abort();
        t.abort();
        let _ = h.stop();
    }
}
