//! Storage duties of a node (ADR 0009, 0014): state snapshots and their announcements, checkpoint
//! sync (start from a snapshot instead of genesis), pruning with history shards, SwarmStorage
//! deals (hosting a user's blocks, keeping the deals assigned to this node) and storage audits.
//!
//! Messages travel on the `/bolt/<chain>/storage` gossip topic: a tag byte, then the payload
//! (a dag-cbor [`SnapshotAnnounce`] or [`DealAnnounce`], or an encoded [`AuditVote`]).

use alloy_consensus::Header;
use alloy_primitives::{B256, U256, keccak256};
use anyhow::{Context, Result, bail};
use bolt_chain::Chain;
use bolt_consensus::{AttestCert, AttestVote, AuditCert, AuditVote, VerdictCert, VerdictVote};
use bolt_ipld::{
    Cid, Envelope,
    deal::DealIndex,
    history::{EpochIndex, SnapshotRoot, decode_group},
};
use bolt_net::{NetEvent, NetHandle};
use bolt_primitives::bls::{BlsPublicKey, BlsSecretKey};
use bolt_store::StateView;
use bolt_system::{abi::*, addresses::*, queries};
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

const TAG_SNAPSHOT: u8 = 1;
const TAG_AUDIT: u8 = 2;
const TAG_DEAL: u8 = 3;
const TAG_VERDICT: u8 = 4;
const TAG_VERIFIER_KEY: u8 = 5;
const TAG_DISPUTE_SHARE: u8 = 6;
const TAG_ATTEST: u8 = 7;

/// How often a node announces its validators' verifier encryption keys.
pub const VERIFIER_KEY_EVERY: Duration = Duration::from_secs(60);

/// A validator's X25519 encryption key for dispute files (ADR 0011), signed with its BLS key.
/// Requesters encrypt the disputed job's files for the panel members' keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKey {
    /// Validator id.
    pub id: u32,
    /// X25519 public key.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    /// BLS signature over [`verifier_key_msg`].
    pub sig: bolt_primitives::bls::BlsSignature,
    /// Sender's clock (unix ms), unsigned: makes each re-announcement a new gossip message
    /// (gossipsub drops repeats of a recent message), as in [`SnapshotAnnounce`].
    #[serde(default)]
    pub at: u64,
}

/// The message a validator signs to publish its verifier key.
pub fn verifier_key_msg(chain_id: u64, id: u32, key: &[u8]) -> Vec<u8> {
    [b"boltchain/verifier-key/v1".as_slice(), &chain_id.to_be_bytes(), &id.to_be_bytes(), key]
        .concat()
}

/// The verifier encryption key pair of a validator (derived from its BLS secret key).
pub fn verifier_vault_key(bls: &BlsSecretKey) -> (bolt_vault::SecretKey, bolt_vault::PublicKey) {
    let ikm = keccak256([b"boltchain/verifier-key/v1".as_slice(), &bls.to_bytes()].concat());
    bolt_vault::SecretKey::derive(ikm.as_slice())
}

/// The disputed job's files re-encrypted for the verifier panel (bolt-vault envelopes that add
/// the panel members as recipients), signed by the job's requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeShare {
    /// Job id.
    pub job: u64,
    /// Input envelope CID.
    #[serde(with = "serde_bytes")]
    pub input: Vec<u8>,
    /// Output envelope CID.
    #[serde(with = "serde_bytes")]
    pub output: Vec<u8>,
    /// Reason envelope CID.
    #[serde(with = "serde_bytes")]
    pub reason: Vec<u8>,
    /// The requester's secp256k1 signature (65 bytes) over [`DisputeShare::digest`].
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl DisputeShare {
    /// The hash the requester signs.
    pub fn digest(chain_id: u64, job: u64, input: &[u8], output: &[u8], reason: &[u8]) -> B256 {
        keccak256(
            [
                b"boltchain/dispute-share/v1".as_slice(),
                &chain_id.to_be_bytes(),
                &job.to_be_bytes(),
                keccak256(input).as_slice(),
                keccak256(output).as_slice(),
                keccak256(reason).as_slice(),
            ]
            .concat(),
        )
    }

    /// The signer's address, if the signature is valid.
    pub fn signer(&self, chain_id: u64) -> Option<alloy_primitives::Address> {
        let sig = alloy_primitives::Signature::from_raw(&self.sig).ok()?;
        let d = Self::digest(chain_id, self.job, &self.input, &self.output, &self.reason);
        sig.recover_address_from_prehash(&d).ok()
    }
}

/// How often a node announces the deal data it can serve.
pub const DEAL_ANNOUNCE_EVERY: Duration = Duration::from_secs(20);
/// How long a node keeps announcing blocks it hosts for a user (until providers took them).
pub const HOSTED_FOR: Duration = Duration::from_secs(3 * 86_400);

/// How often a node re-announces its latest final snapshot.
pub const ANNOUNCE_EVERY: Duration = Duration::from_secs(5);

/// A node has a snapshot of block `number` (`hash`) with root `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotAnnounce {
    /// Block number.
    pub number: u64,
    /// Block hash.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    /// Snapshot root.
    pub root: Cid,
    /// Sender's clock (unix ms) when announcing: makes each re-announcement a new gossip message
    /// (gossipsub drops repeats of a recent message), so nodes that join later still hear it.
    pub at: u64,
}

/// A node serves the blocks of deal index `root` (ADR 0014): providers that must fetch a deal
/// dial one of `addrs` (which end in `/p2p/<peer id>`). A hint only: blocks are verified by CID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealAnnounce {
    /// Deal index root.
    pub root: Cid,
    /// Sender's listen addresses.
    pub addrs: Vec<String>,
    /// Sender's clock (unix ms), as in [`SnapshotAnnounce`].
    pub at: u64,
}

/// A storage-topic message.
#[derive(Debug, Clone)]
pub enum StorageMsg {
    /// Snapshot announcement.
    Snapshot(SnapshotAnnounce),
    /// Audit vote.
    Audit(AuditVote),
    /// Deal data announcement.
    Deal(DealAnnounce),
    /// Compute-dispute verdict vote (ADR 0011).
    Verdict(VerdictVote),
    /// A validator's verifier encryption key.
    VerifierKey(VerifierKey),
    /// Dispute files re-encrypted for the panel.
    DisputeShare(DisputeShare),
    /// TEE attestation vote (ADR 0013).
    Attest(AttestVote),
}

impl StorageMsg {
    /// Encodes for the gossip topic.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            StorageMsg::Snapshot(a) => {
                let mut v = vec![TAG_SNAPSHOT];
                v.extend(serde_ipld_dagcbor::to_vec(a).expect("encodes"));
                v
            }
            StorageMsg::Audit(vote) => {
                let mut v = vec![TAG_AUDIT];
                v.extend(vote.encode());
                v
            }
            StorageMsg::Deal(a) => {
                let mut v = vec![TAG_DEAL];
                v.extend(serde_ipld_dagcbor::to_vec(a).expect("encodes"));
                v
            }
            StorageMsg::Verdict(vote) => {
                let mut v = vec![TAG_VERDICT];
                v.extend(vote.encode());
                v
            }
            StorageMsg::VerifierKey(k) => {
                let mut v = vec![TAG_VERIFIER_KEY];
                v.extend(serde_ipld_dagcbor::to_vec(k).expect("encodes"));
                v
            }
            StorageMsg::DisputeShare(d) => {
                let mut v = vec![TAG_DISPUTE_SHARE];
                v.extend(serde_ipld_dagcbor::to_vec(d).expect("encodes"));
                v
            }
            StorageMsg::Attest(vote) => {
                let mut v = vec![TAG_ATTEST];
                v.extend(vote.encode());
                v
            }
        }
    }

    /// Decodes a gossip message.
    pub fn decode(b: &[u8]) -> Option<Self> {
        let (tag, rest) = b.split_first()?;
        match *tag {
            TAG_SNAPSHOT => serde_ipld_dagcbor::from_slice(rest).ok().map(StorageMsg::Snapshot),
            TAG_AUDIT => AuditVote::decode(rest).map(StorageMsg::Audit),
            TAG_DEAL => serde_ipld_dagcbor::from_slice(rest).ok().map(StorageMsg::Deal),
            TAG_VERDICT => VerdictVote::decode(rest).map(StorageMsg::Verdict),
            TAG_VERIFIER_KEY => {
                serde_ipld_dagcbor::from_slice(rest).ok().map(StorageMsg::VerifierKey)
            }
            TAG_DISPUTE_SHARE => {
                serde_ipld_dagcbor::from_slice(rest).ok().map(StorageMsg::DisputeShare)
            }
            TAG_ATTEST => AttestVote::decode(rest).map(StorageMsg::Attest),
            _ => None,
        }
    }
}

/// Splits the network events: storage messages go to the second receiver, everything else to
/// the first (for the validator or follower loop).
pub fn split(
    mut events: mpsc::Receiver<NetEvent>,
) -> (mpsc::Receiver<NetEvent>, mpsc::Receiver<(PeerId, Vec<u8>)>) {
    let (tx, rx) = mpsc::channel(1024);
    let (stx, srx) = mpsc::channel(1024);
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            match ev {
                NetEvent::Storage { via, data } => {
                    let _ = stx.try_send((via, data));
                }
                other => {
                    if tx.send(other).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    (rx, srx)
}

/// What the storage service does.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Take and announce a snapshot at every epoch end.
    pub snapshots: bool,
    /// Prune block bodies older than the recent window, except epochs assigned to this node's
    /// validators (which it fetches if missing). Off: archive node.
    pub prune: bool,
    /// Validator keys (audit panel duty, shard assignments).
    pub keys: Vec<BlsSecretKey>,
    /// How long an auditor waits for a provider's block.
    pub audit_timeout: Duration,
    /// Accounts whose storage-provider ids (without stake, ADR 0012) this node serves: it keeps
    /// the epochs assigned to them instead of pruning them.
    pub storage_accounts: Vec<alloy_primitives::Address>,
    /// File listing the deal roots this node hosts for its user (kept across restarts).
    pub hosted_file: Option<std::path::PathBuf>,
    /// How this node's validators judge the compute disputes their verifier panel is given
    /// (ADR 0011). `None`: they do not vote (a dispute without a verdict settles for the provider
    /// after 7 days).
    pub verifier: Option<Arc<dyn Judge>>,
    /// TPM vendor roots this node's validators trust when their panel appraises T2 machines
    /// (ADR 0013). Empty: they abstain.
    pub tpm_roots: Vec<Vec<u8>>,
}

/// A disputed compute job, as a verifier sees it.
#[derive(Debug, Clone)]
pub struct DisputedJob {
    /// Job id.
    pub id: u64,
    /// Epoch whose panel decides.
    pub epoch: u64,
    /// Requester.
    pub requester: alloy_primitives::Address,
    /// Provider.
    pub provider: alloy_primitives::Address,
    /// Model id.
    pub model: u64,
    /// Input: bolt-vault envelope CID bytes.
    pub input: Vec<u8>,
    /// Output: bolt-vault envelope CID bytes.
    pub output: Vec<u8>,
    /// Requester's statement: bolt-vault envelope CID bytes.
    pub reason: Vec<u8>,
    /// Token counts the provider claimed.
    pub tokens_in: u64,
    /// Output tokens the provider claimed.
    pub tokens_out: u64,
    /// Whether `input`, `output` and `reason` are the requester's re-encryptions for the panel
    /// (a [`DisputeShare`]); otherwise they are the original envelopes.
    pub shared: bool,
    /// The verifier encryption secret key of one of this node's seats on the panel.
    pub verifier_key: [u8; 32],
}

/// Decides a compute dispute: `Some(true)` when the provider is at fault, `Some(false)` when it
/// is not, `None` to abstain (e.g. the data cannot be read yet). Called on a blocking thread;
/// may take long (re-running a model).
pub trait Judge: Send + Sync + std::fmt::Debug + 'static {
    /// Judges `job`.
    fn judge(&self, job: &DisputedJob) -> Option<bool>;
}

/// A [`Judge`] that runs an external command line (`--verifier-cmd`, run by `sh -c`): the job is
/// passed in environment variables (`BOLT_JOB_ID`, `BOLT_EPOCH`, `BOLT_REQUESTER`,
/// `BOLT_PROVIDER`, `BOLT_MODEL`, `BOLT_INPUT`, `BOLT_OUTPUT`, `BOLT_REASON` as CID strings,
/// `BOLT_SHARED` (1 when those are the requester's re-encryptions for the panel),
/// `BOLT_TOKENS_IN`, `BOLT_TOKENS_OUT`, `BOLT_VERIFIER_KEY` (hex X25519 secret key that opens the
/// shared envelopes), `BOLT_RPC` (this node's JSON-RPC, for `bolt_getBlocks`)); its first output
/// line decides: `fault`, `ok`, anything else abstains. `boltchain judge` is such a program.
#[derive(Debug)]
pub struct CommandJudge {
    /// Command line.
    pub cmd: String,
    /// This node's JSON-RPC URL.
    pub rpc: String,
}

impl Judge for CommandJudge {
    fn judge(&self, job: &DisputedJob) -> Option<bool> {
        let cid = |b: &[u8]| Cid::try_from(b).map(|c| c.to_string()).unwrap_or_default();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&self.cmd)
            .env("BOLT_SHARED", if job.shared { "1" } else { "0" })
            .env("BOLT_VERIFIER_KEY", alloy_primitives::hex::encode(job.verifier_key))
            .env("BOLT_RPC", &self.rpc)
            .env("BOLT_JOB_ID", job.id.to_string())
            .env("BOLT_EPOCH", job.epoch.to_string())
            .env("BOLT_REQUESTER", job.requester.to_string())
            .env("BOLT_PROVIDER", job.provider.to_string())
            .env("BOLT_MODEL", job.model.to_string())
            .env("BOLT_INPUT", cid(&job.input))
            .env("BOLT_OUTPUT", cid(&job.output))
            .env("BOLT_REASON", cid(&job.reason))
            .env("BOLT_TOKENS_IN", job.tokens_in.to_string())
            .env("BOLT_TOKENS_OUT", job.tokens_out.to_string())
            .output()
            .map_err(|e| tracing::warn!("verifier command: {e}"))
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let verdict = match text.lines().next().map(str::trim) {
            Some("fault") => Some(true),
            Some("ok") => Some(false),
            _ => None,
        };
        let detail: Vec<&str> = text.lines().skip(1).collect();
        match verdict {
            Some(fault) => {
                tracing::info!(job = job.id, fault, detail = ?detail, "verifier command decided")
            }
            None => tracing::info!(
                job = job.id,
                output = %text.trim(),
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "verifier command abstained"
            ),
        }
        verdict
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            snapshots: true,
            prune: true,
            keys: vec![],
            audit_timeout: Duration::from_secs(10),
            storage_accounts: vec![],
            hosted_file: None,
            verifier: None,
            tpm_roots: vec![],
        }
    }
}

#[derive(Default)]
struct State {
    /// Snapshot announcements seen (newest last).
    seen: Vec<(PeerId, SnapshotAnnounce)>,
    /// Audit votes by (epoch, task, verdict) and panel position.
    votes: HashMap<(u64, u16, bool), BTreeMap<u16, AuditVote>>,
    /// Tasks certified here.
    certified: HashSet<(u64, u16)>,
    /// (epoch, task, member) this node has voted on.
    audited: HashSet<(u64, u16, u16)>,
    /// Epochs pruned since start.
    pruned: HashSet<u64>,
    /// Panel keys by epoch.
    panels: HashMap<u64, Vec<BlsPublicKey>>,
    /// Deal roots hosted for this node's user, with the time they were hosted (unix s).
    hosted: BTreeMap<Cid, u64>,
    /// Announced sources of deal data: root -> (peer, addresses).
    sources: HashMap<Cid, (PeerId, Vec<Multiaddr>)>,
    /// Deals this node keeps completely: id -> root.
    kept: HashMap<u64, Cid>,
    /// When deal data was last announced.
    deal_announced: Option<Instant>,
    /// Verdict votes by (epoch, job, fault) and panel position.
    verdict_votes: HashMap<(u64, u64, bool), BTreeMap<u16, VerdictVote>>,
    /// Jobs whose verdict was certified here.
    verdict_certified: HashSet<u64>,
    /// (job, member) this node has voted on.
    judged: HashSet<(u64, u16)>,
    /// When a job was last judged without a decision (retried after a minute, or at once when
    /// its files are shared).
    abstained: HashMap<u64, Instant>,
    /// Verifier panel keys by epoch.
    verdict_panels: HashMap<u64, Vec<BlsPublicKey>>,
    /// Jobs below this id are settled or refunded (no need to scan them again).
    job_cursor: u64,
    /// Verifier encryption keys of validators, as announced (checked against their BLS keys).
    verifier_keys: HashMap<u32, [u8; 32]>,
    /// Dispute files shared with the panel, by job.
    shares: HashMap<u64, DisputeShare>,
    /// When this node last announced its verifier keys.
    keys_announced: Option<Instant>,
    /// Attestation votes by (epoch, request, ok, machine) and panel position.
    attest_votes: HashMap<(u64, u64, bool, B256), BTreeMap<u16, AttestVote>>,
    /// Requests certified here.
    attest_certified: HashSet<u64>,
    /// (request, member) this node has voted on.
    attested: HashSet<(u64, u16)>,
    /// When a request was last left undecided (retried after a minute).
    attest_abstained: HashMap<u64, Instant>,
    /// Attestation panel keys by epoch.
    attest_panels: HashMap<u64, Vec<BlsPublicKey>>,
    /// Requests below this id are decided.
    request_cursor: u64,
}

/// The storage service.
pub struct Storage {
    chain: Arc<Chain>,
    net: NetHandle,
    cfg: StorageConfig,
    state: Mutex<State>,
    /// Background jobs running: snapshot, audit, prune, deals, verdicts, attestations.
    busy: [AtomicBool; 6],
}

const SNAPSHOT_JOB: usize = 0;
const AUDIT_JOB: usize = 1;
const PRUNE_JOB: usize = 2;
const DEAL_JOB: usize = 3;
const VERDICT_JOB: usize = 4;
const ATTEST_JOB: usize = 5;

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage").field("cfg", &self.cfg.snapshots).finish()
    }
}

fn view<C: alloy_sol_types::SolCall>(
    chain: &Chain,
    to: alloy_primitives::Address,
    c: C,
) -> Result<C::Return> {
    let r = chain.store().reader()?;
    Ok(queries::call(&StateView::latest(&r), chain.config().chain_id, to, c)?)
}

impl Storage {
    /// Creates the service.
    pub fn new(chain: Arc<Chain>, net: NetHandle, cfg: StorageConfig) -> Arc<Self> {
        let mut state = State::default();
        if let Some(f) = &cfg.hosted_file
            && let Ok(text) = std::fs::read_to_string(f)
        {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                if let (Some(c), Some(t)) = (it.next(), it.next())
                    && let (Ok(c), Ok(t)) = (c.parse::<Cid>(), t.parse::<u64>())
                {
                    state.hosted.insert(c, t);
                }
            }
        }
        Arc::new(Self { chain, net, cfg, state: Mutex::new(state), busy: Default::default() })
    }

    /// Stores a user's blocks (each checked against its CID) and announces deal index `root` to
    /// storage providers for [`HOSTED_FOR`], so they can fetch the deal (ADR 0014).
    pub fn host(&self, root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Result<()> {
        for (c, b) in blocks {
            let got = bolt_ipld::sha256_cid(c.codec(), b);
            if got != *c {
                bail!("block does not match {c}");
            }
        }
        let w = self.chain.store().writer()?;
        for (c, b) in blocks {
            w.put_ipld(c, b)?;
        }
        w.commit()?;
        let now = unix_secs();
        let mut st = self.state.lock();
        st.hosted.insert(root, now);
        st.hosted.retain(|_, t| *t + HOSTED_FOR.as_secs() > now);
        st.deal_announced = None;
        if let Some(f) = &self.cfg.hosted_file {
            let text: String = st.hosted.iter().map(|(c, t)| format!("{c} {t}\n")).collect();
            std::fs::write(f, text)?;
        }
        Ok(())
    }

    /// Reads blocks locally, fetching the missing ones from the network: first from the announced
    /// source of `root` (dialed if needed) and the providers of deal `deal`.
    pub async fn fetch(
        &self,
        cids: &[Cid],
        deal: Option<u64>,
        root: Option<Cid>,
    ) -> Result<HashMap<Cid, Vec<u8>>> {
        let mut peers = Vec::new();
        if let Some(root) = root {
            let src = self.state.lock().sources.get(&root).cloned();
            if let Some((peer, addrs)) = src {
                if !self.net.peers().await.contains(&peer) {
                    for a in addrs {
                        let _ = self.net.dial(a).await;
                    }
                }
                peers.push(peer);
            }
        }
        if let Some(id) = deal {
            for p in self.deal_peers(id, None).await? {
                if !peers.contains(&p) {
                    peers.push(p);
                }
            }
        }
        get_or_fetch(&self.chain, &self.net, cids, &peers).await
    }

    /// Snapshot announcements seen so far (newest last).
    pub fn seen_snapshots(&self) -> Vec<(PeerId, SnapshotAnnounce)> {
        self.state.lock().seen.clone()
    }

    /// Runs until the message stream ends.
    pub async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<(PeerId, Vec<u8>)>) {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut last_announce = Instant::now() - ANNOUNCE_EVERY;
        let mut last_prune = Instant::now();
        let mut last_deals = Instant::now() - Duration::from_secs(2);
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    None => break,
                    Some((via, data)) => self.on_message(via, &data),
                },
                _ = tick.tick() => {
                    if self.cfg.snapshots {
                        self.spawn_guarded(SNAPSHOT_JOB, |s| async move {
                            let chain = s.chain.clone();
                            match tokio::task::spawn_blocking(move || chain.take_snapshot()).await {
                                Ok(Err(e)) => tracing::warn!("snapshot: {e}"),
                                Err(e) => tracing::warn!("snapshot task: {e}"),
                                Ok(Ok(_)) => {}
                            }
                        });
                        if last_announce.elapsed() >= ANNOUNCE_EVERY {
                            last_announce = Instant::now();
                            self.announce().await;
                        }
                    }
                    if !self.cfg.keys.is_empty() {
                        self.spawn_guarded(AUDIT_JOB, |s| async move {
                            if let Err(e) = s.audit_round().await {
                                tracing::debug!("audit round: {e:#}");
                            }
                        });
                    }
                    if self.cfg.prune && last_prune.elapsed() >= Duration::from_secs(2) {
                        last_prune = Instant::now();
                        self.spawn_guarded(PRUNE_JOB, |s| async move {
                            if let Err(e) = s.prune_round().await {
                                tracing::debug!("prune round: {e:#}");
                            }
                        });
                    }
                    if last_deals.elapsed() >= Duration::from_secs(2) {
                        last_deals = Instant::now();
                        self.spawn_guarded(DEAL_JOB, |s| async move {
                            if let Err(e) = s.deal_round().await {
                                tracing::debug!("deal round: {e:#}");
                            }
                        });
                        if !self.cfg.keys.is_empty() {
                            self.spawn_guarded(ATTEST_JOB, |s| async move {
                                if let Err(e) = s.attest_round().await {
                                    tracing::debug!("attestation round: {e:#}");
                                }
                            });
                        }
                        if self.cfg.verifier.is_some() && !self.cfg.keys.is_empty() {
                            self.spawn_guarded(VERDICT_JOB, |s| async move {
                                if let Err(e) = s.verdict_round().await {
                                    tracing::debug!("verdict round: {e:#}");
                                }
                            });
                        }
                    }
                }
            }
        }
    }

    /// Runs job `job` in the background unless it is still running.
    fn spawn_guarded<F, Fut>(self: &Arc<Self>, job: usize, f: F)
    where
        F: FnOnce(Arc<Self>) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        if self.busy[job].swap(true, Ordering::AcqRel) {
            return;
        }
        let fut = f(self.clone());
        let this = self.clone();
        tokio::spawn(async move {
            fut.await;
            this.busy[job].store(false, Ordering::Release);
        });
    }

    /// Publishes every kept snapshot whose block is final.
    async fn announce(&self) {
        let Ok(list) = self.chain.snapshots() else { return };
        for (number, root) in list.into_iter().rev() {
            if !self.chain.is_final(number).unwrap_or(false) {
                continue;
            }
            let Ok(Some(hash)) = self.chain.store().reader().and_then(|r| r.block_hash(number))
            else {
                continue;
            };
            let at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let a = SnapshotAnnounce { number, hash: hash.to_vec(), root, at };
            let _ = self.net.publish_storage(StorageMsg::Snapshot(a).encode()).await;
        }
    }

    fn on_message(&self, via: PeerId, data: &[u8]) {
        match StorageMsg::decode(data) {
            Some(StorageMsg::Snapshot(a)) => {
                let mut st = self.state.lock();
                if !st.seen.iter().any(|(_, s)| s.root == a.root) {
                    st.seen.push((via, a));
                    if st.seen.len() > 32 {
                        st.seen.remove(0);
                    }
                }
            }
            Some(StorageMsg::Audit(v)) => {
                if let Err(e) = self.add_vote(v) {
                    tracing::debug!("audit vote: {e:#}");
                }
            }
            Some(StorageMsg::VerifierKey(k)) => {
                if let Err(e) = self.add_verifier_key(&k) {
                    tracing::debug!("verifier key: {e:#}");
                }
            }
            Some(StorageMsg::DisputeShare(d)) => {
                if let Err(e) = self.add_share(d) {
                    tracing::debug!("dispute share: {e:#}");
                }
            }
            Some(StorageMsg::Verdict(v)) => {
                if let Err(e) = self.add_verdict_vote(v) {
                    tracing::debug!("verdict vote: {e:#}");
                }
            }
            Some(StorageMsg::Attest(v)) => {
                if let Err(e) = self.add_attest_vote(v) {
                    tracing::debug!("attestation vote: {e:#}");
                }
            }
            Some(StorageMsg::Deal(a)) => {
                let addrs: Vec<Multiaddr> =
                    a.addrs.iter().filter_map(|s| s.parse().ok()).take(8).collect();
                let peer = addrs.iter().find_map(|m| {
                    m.iter().find_map(|p| match p {
                        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
                        _ => None,
                    })
                });
                if let Some(peer) = peer {
                    let mut st = self.state.lock();
                    if st.sources.len() >= 4096 {
                        st.sources.clear();
                    }
                    st.sources.insert(a.root, (peer, addrs));
                }
            }
            None => tracing::debug!(%via, "undecodable storage message"),
        }
    }

    fn panel_keys(&self, epoch: u64) -> Result<Vec<BlsPublicKey>> {
        if let Some(k) = self.state.lock().panels.get(&epoch) {
            return Ok(k.clone());
        }
        let a = view(&self.chain, SWARM, ISwarmStorage::auditsCall { epoch })?;
        if a.panel.is_empty() {
            return Ok(vec![]);
        }
        let keys = view(&self.chain, STAKING, IStakingManager::keysOfCall { ids: a.panel })?;
        let keys: Vec<BlsPublicKey> =
            keys.pubkeys.chunks_exact(48).map(BlsPublicKey::from_slice).collect();
        let mut st = self.state.lock();
        st.panels.insert(epoch, keys.clone());
        st.panels.retain(|e, _| *e + 4 > epoch);
        Ok(keys)
    }

    /// Checks a vote, counts it, and queues the certificate once more than 2/3 of the panel
    /// agree.
    fn add_vote(&self, vote: AuditVote) -> Result<()> {
        let chain_id = self.chain.config().chain_id;
        let panel = self.panel_keys(vote.epoch)?;
        if panel.is_empty() || !vote.verify(chain_id, &panel) {
            bail!("vote does not verify against the panel of epoch {}", vote.epoch);
        }
        let key = (vote.epoch, vote.task, vote.passed);
        let mut st = self.state.lock();
        if st.certified.contains(&(vote.epoch, vote.task)) {
            return Ok(());
        }
        let votes = st.votes.entry(key).or_default();
        votes.insert(vote.member, vote.clone());
        if votes.len() * 3 > panel.len() * 2 {
            let all: Vec<AuditVote> = votes.values().cloned().collect();
            if let Some(cert) = AuditCert::aggregate(&all, panel.len()) {
                tracing::info!(
                    epoch = vote.epoch,
                    task = vote.task,
                    passed = vote.passed,
                    votes = all.len(),
                    "storage audit certified"
                );
                st.certified.insert((vote.epoch, vote.task));
                bolt_primitives::metrics::AUDITS_CERTIFIED.inc();
                let epoch = vote.epoch;
                st.votes.retain(|(e, _, _), _| *e + 2 > epoch);
                drop(st);
                self.chain.add_audit_cert(cert.encode());
            }
        }
        Ok(())
    }

    /// Provider ids this node serves: its validator keys' ids (mapped to the key index) and the
    /// active storage-provider ids of `storage_accounts` (mapped to `usize::MAX`: no key, they
    /// never sit on a panel).
    fn my_ids(&self) -> Result<HashMap<u32, usize>> {
        let mut out = HashMap::new();
        for (i, k) in self.cfg.keys.iter().enumerate() {
            let h = keccak256(k.public_key().as_slice());
            let id = view(&self.chain, STAKING, IStakingManager::idOfPubkeyCall { h })?;
            if id != 0 {
                out.insert(id, i);
            }
        }
        for account in &self.cfg.storage_accounts {
            let ids =
                view(&self.chain, SWARM, ISwarmStorage::storageIdsOfCall { account: *account })?;
            for id in ids {
                let p = view(&self.chain, SWARM, ISwarmStorage::storageProviderCall { id })?;
                if p.active {
                    out.insert(id, usize::MAX);
                }
            }
        }
        Ok(out)
    }

    /// Serves the panel duty for the current epoch: probe every pending task's provider once and
    /// vote.
    async fn audit_round(&self) -> Result<()> {
        let head = self.chain.head()?.number;
        let epoch = self.chain.rules().epoch_of(head + 1);
        let a = view(&self.chain, SWARM, ISwarmStorage::auditsCall { epoch })?;
        if a.panel.is_empty() {
            return Ok(());
        }
        // Before SwarmStorage (testnet `swarm` fork) every task is a history task.
        let kinds =
            view(&self.chain, SWARM, ISwarmStorage::taskKindsCall { epoch }).unwrap_or_default();
        let mine = self.my_ids()?;
        let members: Vec<(u16, usize)> = a
            .panel
            .iter()
            .enumerate()
            .filter_map(|(m, id)| {
                mine.get(id).filter(|k| **k != usize::MAX).map(|k| (m as u16, *k))
            })
            .collect();
        if members.is_empty() {
            return Ok(());
        }
        let chain_id = self.chain.config().chain_id;
        for (task, state) in a.states.iter().enumerate() {
            let task16 = task as u16;
            if *state != 0 || self.state.lock().certified.contains(&(epoch, task16)) {
                continue;
            }
            let todo: Vec<(u16, usize)> = {
                let st = self.state.lock();
                members
                    .iter()
                    .copied()
                    .filter(|(m, _)| !st.audited.contains(&(epoch, task16, *m)))
                    .collect()
            };
            if todo.is_empty() {
                continue;
            }
            let passed = if kinds.get(task) == Some(&1) {
                self.check_deal(a.providers[task], a.targets[task], a.heights[task], &mine).await
            } else {
                self.check_provider(a.providers[task], a.heights[task], &mine).await
            };
            tracing::debug!(epoch, task, provider = a.providers[task], passed, "audited");
            for (m, k) in todo {
                let vote = AuditVote::sign(&self.cfg.keys[k], chain_id, epoch, task16, passed, m);
                self.state.lock().audited.insert((epoch, task16, m));
                bolt_primitives::metrics::AUDIT_VOTES.inc();
                let _ = self.net.publish_storage(StorageMsg::Audit(vote.clone()).encode()).await;
                self.add_vote(vote)?;
            }
        }
        Ok(())
    }

    /// Whether `provider` serves data of block `height`: the first body chunk (or the envelope
    /// of an empty block), asked from its registered peer only.
    async fn check_provider(&self, provider: u32, height: u64, mine: &HashMap<u32, usize>) -> bool {
        let target = {
            let Ok(r) = self.chain.store().reader() else { return false };
            let Ok(Some(root)) = r.envelope_root(height) else { return false };
            match r.ipld(&root).ok().flatten().and_then(|b| Envelope::decode(&b).ok()) {
                Some(env) => env.chunks.first().copied().unwrap_or(root),
                None => root,
            }
        };
        if mine.contains_key(&provider) {
            return self
                .chain
                .store()
                .reader()
                .ok()
                .and_then(|r| r.ipld(&target).ok().flatten())
                .is_some();
        }
        let Ok(peer) = view(&self.chain, SWARM, ISwarmStorage::peerOfCall { id: provider }) else {
            return false;
        };
        let Ok(peer) = PeerId::from_bytes(&peer) else { return false };
        self.net.probe(target, peer, self.cfg.audit_timeout).await.is_ok()
    }

    /// Keys of the compute verifier panel of `epoch` (ComputeMarket), cached.
    fn verdict_panel_keys(&self, epoch: u64) -> Result<Vec<BlsPublicKey>> {
        if let Some(k) = self.state.lock().verdict_panels.get(&epoch) {
            return Ok(k.clone());
        }
        let ids = view(&self.chain, COMPUTE, IComputeMarket::panelCall { epoch })?;
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let keys = view(&self.chain, STAKING, IStakingManager::keysOfCall { ids })?;
        let keys: Vec<BlsPublicKey> =
            keys.pubkeys.chunks_exact(48).map(BlsPublicKey::from_slice).collect();
        let mut st = self.state.lock();
        st.verdict_panels.insert(epoch, keys.clone());
        if st.verdict_panels.len() > 64 {
            let oldest = *st.verdict_panels.keys().min().expect("non-empty");
            st.verdict_panels.remove(&oldest);
        }
        Ok(keys)
    }

    /// Checks an announced verifier key against the validator's BLS key and keeps it.
    fn add_verifier_key(&self, k: &VerifierKey) -> Result<()> {
        let key: [u8; 32] = k.key.as_slice().try_into().context("key length")?;
        if self.state.lock().verifier_keys.get(&k.id) == Some(&key) {
            return Ok(());
        }
        let keys = view(&self.chain, STAKING, IStakingManager::keysOfCall { ids: vec![k.id] })?;
        let pk =
            keys.pubkeys.get(..48).map(BlsPublicKey::from_slice).context("unknown validator")?;
        let chain_id = self.chain.config().chain_id;
        if !bolt_primitives::bls::verify(&pk, &verifier_key_msg(chain_id, k.id, &key), &k.sig) {
            bail!("bad signature on the verifier key of validator {}", k.id);
        }
        self.state.lock().verifier_keys.insert(k.id, key);
        Ok(())
    }

    /// Announces this node's validators' verifier keys (every [`VERIFIER_KEY_EVERY`]).
    async fn announce_verifier_keys(&self) {
        {
            let mut st = self.state.lock();
            if st.keys_announced.is_some_and(|t| t.elapsed() < VERIFIER_KEY_EVERY) {
                return;
            }
            st.keys_announced = Some(Instant::now());
        }
        let Ok(mine) = self.my_ids() else { return };
        let chain_id = self.chain.config().chain_id;
        for (id, k) in mine {
            if k == usize::MAX {
                continue;
            }
            let (_, pk) = verifier_vault_key(&self.cfg.keys[k]);
            let key = pk.to_bytes().to_vec();
            let msg = VerifierKey {
                id,
                sig: self.cfg.keys[k].sign(&verifier_key_msg(chain_id, id, &key)),
                key,
                at: unix_secs() * 1000,
            };
            let _ = self.add_verifier_key(&msg);
            let _ = self.net.publish_storage(StorageMsg::VerifierKey(msg).encode()).await;
        }
    }

    /// Verifier keys known for `ids` (hex), in order.
    pub fn verifier_keys(&self, ids: &[u32]) -> Vec<Option<String>> {
        let st = self.state.lock();
        ids.iter()
            .map(|id| st.verifier_keys.get(id).map(alloy_primitives::hex::encode_prefixed))
            .collect()
    }

    /// Checks a dispute share (signed by the job's requester, job still disputed) and keeps it.
    fn add_share(&self, d: DisputeShare) -> Result<bool> {
        let chain_id = self.chain.config().chain_id;
        if self.state.lock().shares.get(&d.job) == Some(&d) {
            return Ok(false);
        }
        let j = view(&self.chain, COMPUTE, IComputeMarket::jobCall { id: U256::from(d.job) })?;
        if j.state != 4 {
            bail!("job {} is not disputed", d.job);
        }
        if d.signer(chain_id) != Some(j.requester) {
            bail!("dispute share of job {} not signed by its requester", d.job);
        }
        let mut st = self.state.lock();
        if st.shares.len() >= 4096 {
            st.shares.clear();
        }
        // The files are readable now: judge again without waiting.
        st.abstained.remove(&d.job);
        st.shares.insert(d.job, d);
        Ok(true)
    }

    /// Accepts a dispute share from this node's user and gossips it to the panel.
    pub async fn share_dispute(&self, d: DisputeShare) -> Result<()> {
        self.add_share(d.clone())?;
        self.state.lock().abstained.remove(&d.job);
        let _ = self.net.publish_storage(StorageMsg::DisputeShare(d).encode()).await;
        Ok(())
    }

    /// Checks a verdict vote, counts it, and queues the certificate once more than 2/3 of the
    /// panel agree.
    fn add_verdict_vote(&self, vote: VerdictVote) -> Result<()> {
        let chain_id = self.chain.config().chain_id;
        let panel = self.verdict_panel_keys(vote.epoch)?;
        if panel.is_empty() || !vote.verify(chain_id, &panel) {
            bail!("verdict vote does not verify against the panel of epoch {}", vote.epoch);
        }
        let mut st = self.state.lock();
        if st.verdict_certified.contains(&vote.job) {
            return Ok(());
        }
        let votes = st.verdict_votes.entry((vote.epoch, vote.job, vote.fault)).or_default();
        votes.insert(vote.member, vote.clone());
        if votes.len() * 3 > panel.len() * 2 {
            let all: Vec<VerdictVote> = votes.values().cloned().collect();
            if let Some(cert) = VerdictCert::aggregate(&all, panel.len()) {
                tracing::info!(
                    job = vote.job,
                    fault = vote.fault,
                    votes = all.len(),
                    "compute verdict certified"
                );
                st.verdict_certified.insert(vote.job);
                st.verdict_votes.retain(|(_, j, _), _| *j != vote.job);
                drop(st);
                self.chain.add_audit_cert(cert.encode());
            }
        }
        Ok(())
    }

    /// Verifier duty (ADR 0011): for every disputed job assigned to a panel this node's
    /// validators sit on, judge it once and vote for each of their seats.
    async fn verdict_round(&self) -> Result<()> {
        let Some(judge) = self.cfg.verifier.clone() else { return Ok(()) };
        let count = view(&self.chain, COMPUTE, IComputeMarket::jobCountCall {})?.to::<u64>();
        let mine = self.my_ids()?;
        let chain_id = self.chain.config().chain_id;
        let start = self.state.lock().job_cursor;
        let mut cursor = start;
        let mut advancing = true;
        for id in start..count {
            let j = view(&self.chain, COMPUTE, IComputeMarket::jobCall { id: U256::from(id) })?;
            // Settled (5) or refunded (6): final.
            if advancing && (j.state == 5 || j.state == 6) {
                cursor = id + 1;
                continue;
            }
            advancing = false;
            if j.state != 4 || self.state.lock().verdict_certified.contains(&id) {
                continue;
            }
            let d =
                view(&self.chain, COMPUTE, IComputeMarket::disputesCall { id: U256::from(id) })?;
            if d.panelEpoch == 0 {
                continue;
            }
            let panel =
                view(&self.chain, COMPUTE, IComputeMarket::panelCall { epoch: d.panelEpoch })?;
            let seats: Vec<(u16, usize)> = panel
                .iter()
                .enumerate()
                .filter_map(|(m, v)| {
                    mine.get(v).filter(|k| **k != usize::MAX).map(|k| (m as u16, *k))
                })
                .filter(|(m, _)| !self.state.lock().judged.contains(&(id, *m)))
                .collect();
            if seats.is_empty() {
                continue;
            }
            if self
                .state
                .lock()
                .abstained
                .get(&id)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
            {
                continue;
            }
            let share = self.state.lock().shares.get(&id).cloned();
            let (vsk, _) = verifier_vault_key(&self.cfg.keys[seats[0].1]);
            let job = DisputedJob {
                id,
                epoch: d.panelEpoch,
                requester: j.requester,
                provider: j.provider,
                model: j.model,
                input: share.as_ref().map(|s| s.input.clone()).unwrap_or_else(|| j.input.to_vec()),
                output: share
                    .as_ref()
                    .map(|s| s.output.clone())
                    .unwrap_or_else(|| j.output.to_vec()),
                reason: share
                    .as_ref()
                    .map(|s| s.reason.clone())
                    .unwrap_or_else(|| d.reason.to_vec()),
                tokens_in: j.tokensIn,
                tokens_out: j.tokensOut,
                shared: share.is_some(),
                verifier_key: vsk.to_bytes(),
            };
            let judge = judge.clone();
            let verdict = tokio::task::spawn_blocking(move || judge.judge(&job)).await?;
            let Some(fault) = verdict else {
                self.state.lock().abstained.insert(id, Instant::now());
                continue;
            };
            tracing::info!(job = id, fault, "judged compute dispute");
            for (m, k) in seats {
                let vote =
                    VerdictVote::sign(&self.cfg.keys[k], chain_id, d.panelEpoch, id, fault, m);
                self.state.lock().judged.insert((id, m));
                let _ = self.net.publish_storage(StorageMsg::Verdict(vote.clone()).encode()).await;
                self.add_verdict_vote(vote)?;
            }
        }
        self.state.lock().job_cursor = cursor;
        Ok(())
    }

    /// Keys of the attestation panel of `epoch` (EnclaveLease), cached.
    fn attest_panel_keys(&self, epoch: u64) -> Result<Vec<BlsPublicKey>> {
        if let Some(k) = self.state.lock().attest_panels.get(&epoch) {
            return Ok(k.clone());
        }
        let ids = view(&self.chain, LEASES, IEnclaveLease::panelCall { epoch })?;
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let keys = view(&self.chain, STAKING, IStakingManager::keysOfCall { ids })?;
        let keys: Vec<BlsPublicKey> =
            keys.pubkeys.chunks_exact(48).map(BlsPublicKey::from_slice).collect();
        let mut st = self.state.lock();
        st.attest_panels.insert(epoch, keys.clone());
        if st.attest_panels.len() > 64 {
            let oldest = *st.attest_panels.keys().min().expect("non-empty");
            st.attest_panels.remove(&oldest);
        }
        Ok(keys)
    }

    /// Checks an attestation vote, counts it, and queues the certificate once more than 2/3 of
    /// the panel agree.
    fn add_attest_vote(&self, vote: AttestVote) -> Result<()> {
        let chain_id = self.chain.config().chain_id;
        let panel = self.attest_panel_keys(vote.epoch)?;
        if panel.is_empty() || !vote.verify(chain_id, &panel) {
            bail!("attestation vote does not verify against the panel of epoch {}", vote.epoch);
        }
        let machine = B256::from_slice(&vote.machine);
        let mut st = self.state.lock();
        if st.attest_certified.contains(&vote.request) {
            return Ok(());
        }
        let votes = st.attest_votes.entry((vote.epoch, vote.request, vote.ok, machine)).or_default();
        votes.insert(vote.member, vote.clone());
        if votes.len() * 3 > panel.len() * 2 {
            let all: Vec<AttestVote> = votes.values().cloned().collect();
            if let Some(cert) = AttestCert::aggregate(&all, panel.len()) {
                tracing::info!(
                    request = vote.request,
                    ok = vote.ok,
                    votes = all.len(),
                    "TEE attestation certified"
                );
                st.attest_certified.insert(vote.request);
                st.attest_votes.retain(|(_, r, _, _), _| *r != vote.request);
                drop(st);
                self.chain.add_audit_cert(cert.encode());
            }
        }
        Ok(())
    }

    /// Verifier duty (ADR 0013 §6.4): for every attestation request assigned to a panel this
    /// node's validators sit on, appraise the machine's evidence once and vote for each seat.
    async fn attest_round(&self) -> Result<()> {
        let chain_id = self.chain.config().chain_id;
        let head = self.chain.head()?.number;
        if !bolt_primitives::forks::active(chain_id, bolt_primitives::forks::TEE, head) {
            return Ok(());
        }
        let count = view(&self.chain, LEASES, IEnclaveLease::requestCountCall {})?.to::<u64>();
        let start = self.state.lock().request_cursor.max(1);
        let mut cursor = start;
        let mut advancing = true;
        let mine = self.my_ids()?;
        for id in start..=count {
            let chain = self.chain.clone();
            let call = move |to: alloy_primitives::Address, data: Vec<u8>| -> Result<Vec<u8>> {
                let r = chain.store().reader()?;
                Ok(queries::call_raw(&StateView::latest(&r), chain.config().chain_id, to, data)?
                    .to_vec())
            };
            let Some(p) = crate::attest::pending(id, call)? else {
                let r = view(&self.chain, LEASES, IEnclaveLease::requestCall { r: U256::from(id) })?;
                if advancing && r.state != 1 {
                    cursor = id + 1;
                }
                continue;
            };
            advancing = false;
            if self.state.lock().attest_certified.contains(&id) {
                continue;
            }
            let panel = view(&self.chain, LEASES, IEnclaveLease::panelCall { epoch: p.request.epoch })?;
            let seats: Vec<(u16, usize)> = panel
                .iter()
                .enumerate()
                .filter_map(|(m, v)| mine.get(v).filter(|k| **k != usize::MAX).map(|k| (m as u16, *k)))
                .filter(|(m, _)| !self.state.lock().attested.contains(&(id, *m)))
                .collect();
            if seats.is_empty()
                || self
                    .state
                    .lock()
                    .attest_abstained
                    .get(&id)
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
            {
                continue;
            }
            let roots = self.cfg.tpm_roots.clone();
            let chain = self.chain.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let allows = |image: u64, m: B256| -> Result<bool> {
                    view(&chain, IMAGES, IImageRegistry::allowsCall { id: image, kind: 3, m })
                };
                crate::attest::appraise(&p, &roots, unix_secs(), allows)
            })
            .await?;
            let Some((ok, machine)) = outcome else {
                self.state.lock().attest_abstained.insert(id, Instant::now());
                continue;
            };
            let epoch = view(&self.chain, LEASES, IEnclaveLease::requestCall { r: U256::from(id) })?.epoch;
            for (m, k) in seats {
                let vote = AttestVote::sign(&self.cfg.keys[k], chain_id, epoch, id, ok, machine.0, m);
                self.state.lock().attested.insert((id, m));
                let _ = self.net.publish_storage(StorageMsg::Attest(vote.clone()).encode()).await;
                self.add_attest_vote(vote)?;
            }
        }
        self.state.lock().request_cursor = cursor;
        Ok(())
    }

    /// Whether `provider` serves block `index` of deal `id`: the deal index (root and group) is
    /// fetched from the provider first, then from anyone; the block itself only from the
    /// provider's registered peer. A position past the index's end is the owner's fault: pass.
    async fn check_deal(
        &self,
        provider: u32,
        id: u64,
        index: u64,
        mine: &HashMap<u32, usize>,
    ) -> bool {
        let Ok(d) = view(&self.chain, SWARM, ISwarmStorage::dealCall { id: U256::from(id) }) else {
            return false;
        };
        let Ok(root) = Cid::try_from(d.root.as_ref()) else { return true };
        let peer = view(&self.chain, SWARM, ISwarmStorage::peerOfCall { id: provider })
            .ok()
            .and_then(|p| PeerId::from_bytes(&p).ok());
        let local = mine.contains_key(&provider);
        let hint: Vec<PeerId> = peer.into_iter().collect();
        let leaf = async {
            let got = get_or_fetch(&self.chain, &self.net, &[root], &hint).await.ok()?;
            let idx = DealIndex::decode(&got[&root]).ok()?;
            let Some((group, pos)) = idx.locate(index) else { return Some(None) };
            let got = get_or_fetch(&self.chain, &self.net, &[group], &hint).await.ok()?;
            let list = bolt_ipld::deal::decode_group(&got[&group]).ok()?;
            list.get(pos).copied().map(Some)
        }
        .await;
        let leaf = match leaf {
            None => return false, // index missing or malformed: the provider keeps it too
            Some(None) => return true, // past the end of the index
            Some(Some(c)) => c,
        };
        if local {
            return self
                .chain
                .store()
                .reader()
                .ok()
                .and_then(|r| r.ipld(&leaf).ok().flatten())
                .is_some();
        }
        let Some(peer) = peer else { return false };
        self.net.probe(leaf, peer, self.cfg.audit_timeout).await.is_ok()
    }

    /// Deals (ADR 0014): announces the deal data this node can serve (hosted for its user, or
    /// kept for a deal with a copy still in its first epoch), and fetches the deals assigned to
    /// its provider ids.
    async fn deal_round(&self) -> Result<()> {
        let Ok(count) = view(&self.chain, SWARM, ISwarmStorage::dealCountCall {}) else {
            return Ok(()); // before SwarmStorage
        };
        let epoch = self.chain.rules().epoch_of(self.chain.head()?.number + 1);
        self.announce_deals(epoch).await;
        self.announce_verifier_keys().await;
        if count.is_zero() {
            return Ok(());
        }
        let mine = self.my_ids()?;
        let mut seen = HashSet::new();
        for id in mine.keys() {
            let deals = view(&self.chain, SWARM, ISwarmStorage::dealsOfCall { id: *id })?;
            for d in deals {
                let d = d.to::<u64>();
                if !seen.insert(d) || self.state.lock().kept.contains_key(&d) {
                    continue;
                }
                let slots =
                    view(&self.chain, SWARM, ISwarmStorage::dealSlotsCall { id: U256::from(d) })?;
                let holds =
                    (0..slots.providers.len()).any(|k| slots.open[k] && slots.providers[k] == *id);
                let info = view(&self.chain, SWARM, ISwarmStorage::dealCall { id: U256::from(d) })?;
                if !holds || info.closed || epoch >= info.endEpoch {
                    continue;
                }
                let Ok(root) = Cid::try_from(info.root.as_ref()) else { continue };
                let peers = self.deal_peers(d, Some(root)).await?;
                match self.ensure_deal(root, &peers).await {
                    Ok(n) => {
                        tracing::info!(deal = d, blocks = n, "keeping deal");
                        self.state.lock().kept.insert(d, root);
                    }
                    Err(e) => tracing::debug!(deal = d, "deal data not complete yet: {e:#}"),
                }
            }
        }
        Ok(())
    }

    /// Peers to fetch deal `id` from: the announced source of its root (dialed), then the other
    /// providers holding it.
    async fn deal_peers(&self, id: u64, root: Option<Cid>) -> Result<Vec<PeerId>> {
        let mut peers = Vec::new();
        let root = match root {
            Some(r) => Some(r),
            None => view(&self.chain, SWARM, ISwarmStorage::dealCall { id: U256::from(id) })
                .ok()
                .and_then(|d| Cid::try_from(d.root.as_ref()).ok()),
        };
        if let Some(root) = root {
            let src = self.state.lock().sources.get(&root).cloned();
            if let Some((peer, addrs)) = src {
                if !self.net.peers().await.contains(&peer) {
                    for a in addrs {
                        let _ = self.net.dial(a).await;
                    }
                }
                peers.push(peer);
            }
        }
        let slots = view(&self.chain, SWARM, ISwarmStorage::dealSlotsCall { id: U256::from(id) })?;
        for (k, p) in slots.providers.iter().enumerate() {
            if !slots.open[k] {
                continue;
            }
            let peer = view(&self.chain, SWARM, ISwarmStorage::peerOfCall { id: *p })?;
            if let Ok(peer) = PeerId::from_bytes(&peer)
                && peer != self.net.peer_id()
                && !peers.contains(&peer)
            {
                peers.push(peer);
            }
        }
        Ok(peers)
    }

    /// Makes sure every block of a deal (index and listed blocks) is in the local blockstore;
    /// returns the number of listed blocks.
    async fn ensure_deal(&self, root: Cid, peers: &[PeerId]) -> Result<u64> {
        let got = get_or_fetch(&self.chain, &self.net, &[root], peers).await?;
        let idx = DealIndex::decode(&got[&root])?;
        let groups = get_or_fetch(&self.chain, &self.net, &idx.groups, peers).await?;
        let mut leaves = Vec::new();
        for g in &idx.groups {
            leaves.extend(bolt_ipld::deal::decode_group(&groups[g])?);
        }
        if leaves.len() as u64 != idx.count {
            bail!("deal index lists {} blocks, says {}", leaves.len(), idx.count);
        }
        let got = get_or_fetch(&self.chain, &self.net, &leaves, peers).await?;
        if got.len() < leaves.iter().collect::<HashSet<_>>().len() {
            bail!("deal incomplete");
        }
        Ok(idx.count)
    }

    async fn announce_deals(&self, epoch: u64) {
        let (roots, kept) = {
            let mut st = self.state.lock();
            if st.deal_announced.is_some_and(|t| t.elapsed() < DEAL_ANNOUNCE_EVERY) {
                return;
            }
            st.deal_announced = Some(Instant::now());
            let now = unix_secs();
            let hosted: Vec<Cid> = st
                .hosted
                .iter()
                .filter(|(_, t)| **t + HOSTED_FOR.as_secs() > now)
                .map(|(c, _)| *c)
                .collect();
            (hosted, st.kept.clone())
        };
        let mut roots = roots;
        for (id, root) in kept {
            // Only while a copy is new (in its first epoch) and may still need the data.
            if let Ok(s) =
                view(&self.chain, SWARM, ISwarmStorage::dealSlotsCall { id: U256::from(id) })
                && (0..s.providers.len()).any(|k| s.open[k] && s.since[k] + 1 >= epoch)
                && !roots.contains(&root)
            {
                roots.push(root);
            }
        }
        if roots.is_empty() {
            return;
        }
        let addrs: Vec<String> =
            self.net.listen_addrs().await.iter().map(|a| a.to_string()).collect();
        let at = unix_secs() * 1000;
        for root in roots {
            let a = DealAnnounce { root, addrs: addrs.clone(), at };
            let _ = self.net.publish_storage(StorageMsg::Deal(a).encode()).await;
        }
    }

    /// Prunes epochs older than the recent window that no local validator keeps, and completes
    /// the ones they keep.
    async fn prune_round(&self) -> Result<()> {
        let rules = *self.chain.rules();
        let head = self.chain.head()?.number;
        let Some(last_old) = rules.epoch_of(head).checked_sub(rules.history_recent_epochs + 1)
        else {
            return Ok(());
        };
        let mut validators =
            view(&self.chain, STAKING, IStakingManager::snapshotCall { minAge: 0 })?.ids;
        validators.sort_unstable();
        let storage = view(&self.chain, SWARM, ISwarmStorage::activeStorageProvidersCall {})?;
        let mine = self.my_ids()?;
        for e in 0..=last_old {
            let idx = view(&self.chain, SWARM, ISwarmStorage::epochIndexCall { epoch: e })?;
            if idx.is_empty() {
                continue;
            }
            let who = bolt_system::history::assignees(&idx, &validators, &storage);
            if who.iter().any(|id| mine.contains_key(id)) {
                let cid = Cid::try_from(idx.as_ref()).context("epoch index cid")?;
                self.ensure_epoch(cid).await?;
            } else if !self.state.lock().pruned.contains(&e) {
                let chain = self.chain.clone();
                let n = tokio::task::spawn_blocking(move || chain.prune_epoch(e)).await??;
                if n > 0 {
                    bolt_primitives::metrics::BLOCKS_PRUNED.add(n);
                    tracing::info!(epoch = e, blocks = n, "pruned history");
                }
                self.state.lock().pruned.insert(e);
            }
        }
        Ok(())
    }

    /// Makes sure every block of an epoch's history is in the local blockstore, fetching what is
    /// missing from peers.
    async fn ensure_epoch(&self, index: Cid) -> Result<()> {
        let idx = EpochIndex::decode(&self.get_or_fetch(&[index]).await?[&index])?;
        let groups = self.get_or_fetch(&idx.groups).await?;
        let mut envelopes = Vec::new();
        for g in &idx.groups {
            envelopes.extend(decode_group(&groups[g])?);
        }
        let envs = self.get_or_fetch(&envelopes).await?;
        let mut parts = Vec::new();
        for c in &envelopes {
            let e = Envelope::decode(&envs[c])?;
            parts.push(e.header);
            parts.extend(e.chunks);
        }
        let got = self.get_or_fetch(&parts).await?;
        if got.len() < parts.iter().collect::<HashSet<_>>().len() {
            bail!("epoch {} incomplete", idx.epoch);
        }
        Ok(())
    }

    /// Reads blocks locally, fetching (and storing) the missing ones.
    async fn get_or_fetch(&self, cids: &[Cid]) -> Result<HashMap<Cid, Vec<u8>>> {
        get_or_fetch(&self.chain, &self.net, cids, &[]).await
    }
}

/// JSON-RPC block hosting (`--rpc-storage`) backed by the storage service.
#[derive(Debug)]
pub struct RpcHost {
    /// Storage service.
    pub storage: Arc<Storage>,
    /// Runtime for the network fetches (RPC handlers run on blocking threads).
    pub rt: tokio::runtime::Handle,
}

impl bolt_rpc::BlockHost for RpcHost {
    fn host(&self, root: String, blocks: Vec<(String, Vec<u8>)>) -> Result<(), String> {
        let root: Cid = root.parse().map_err(|e| format!("root: {e}"))?;
        let blocks = blocks
            .into_iter()
            .map(|(c, b)| c.parse::<Cid>().map(|c| (c, b)).map_err(|e| format!("cid: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        self.storage.host(root, &blocks).map_err(|e| format!("{e:#}"))
    }

    fn fetch(
        &self,
        cids: Vec<String>,
        deal: Option<u64>,
        root: Option<String>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let cids = cids
            .iter()
            .map(|c| c.parse::<Cid>().map_err(|e| format!("cid: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let root = root.map(|r| r.parse::<Cid>()).transpose().map_err(|e| format!("root: {e}"))?;
        let got = self
            .rt
            .block_on(self.storage.fetch(&cids, deal, root))
            .map_err(|e| format!("{e:#}"))?;
        cids.iter().map(|c| got.get(c).cloned().ok_or_else(|| format!("{c} not found"))).collect()
    }

    fn verifier_keys(&self, ids: Vec<u32>) -> Vec<Option<String>> {
        self.storage.verifier_keys(&ids)
    }

    fn share_dispute(&self, job: u64, envelopes: [String; 3], sig: Vec<u8>) -> Result<(), String> {
        let [input, output, reason] = envelopes;
        let d = DisputeShare {
            job,
            input: Self::parse_cid(&input)?,
            output: Self::parse_cid(&output)?,
            reason: Self::parse_cid(&reason)?,
            sig,
        };
        self.rt.block_on(self.storage.share_dispute(d)).map_err(|e| format!("{e:#}"))
    }
}

impl RpcHost {
    fn parse_cid(s: &str) -> Result<Vec<u8>, String> {
        s.parse::<Cid>().map(|c| c.to_bytes()).map_err(|e| format!("cid {s}: {e}"))
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads blocks from the local blockstore, fetching the missing ones from `peers` (then any
/// connected peer) in batches and storing them.
pub async fn get_or_fetch(
    chain: &Chain,
    net: &NetHandle,
    cids: &[Cid],
    peers: &[PeerId],
) -> Result<HashMap<Cid, Vec<u8>>> {
    let mut out = HashMap::new();
    let mut missing = Vec::new();
    {
        let r = chain.store().reader()?;
        for c in cids {
            match r.ipld(c)? {
                Some(b) => {
                    out.insert(*c, b);
                }
                None => missing.push(*c),
            }
        }
    }
    if missing.is_empty() {
        return Ok(out);
    }
    let mut sources = peers.to_vec();
    sources.extend(net.peers().await.into_iter().filter(|p| !peers.contains(p)));
    for batch in missing.chunks(64) {
        let mut got = HashMap::new();
        for attempt in 0..4 {
            let want: Vec<Cid> = batch.iter().filter(|c| !got.contains_key(*c)).copied().collect();
            match net.fetch(&want, &sources).await {
                Ok(m) => {
                    got.extend(m);
                    break;
                }
                Err(e) if attempt == 3 => return Err(e.into()),
                Err(_) => {}
            }
        }
        let w = chain.store().writer()?;
        for (c, b) in &got {
            w.put_ipld(c, b)?;
        }
        w.commit()?;
        out.extend(got);
    }
    Ok(out)
}

/// Starts a fresh node from the snapshot of trusted block `number` (`hash`): the snapshot root
/// is `root` if given, else taken from the first matching announcement on `storage`. Fetches the
/// state, the block and its recent ancestors over Bitswap, rebuilds and checks the state, and
/// makes the block the head. Blocks after it then sync as usual.
pub async fn checkpoint_sync(
    chain: &Arc<Chain>,
    net: &NetHandle,
    number: u64,
    hash: B256,
    root: Option<Cid>,
    storage: &mut mpsc::Receiver<(PeerId, Vec<u8>)>,
) -> Result<Header> {
    let head = chain.head()?;
    if head.number != 0 {
        let known = chain.store().reader()?.block_hash(number)?;
        if known == Some(hash) || head.number > number {
            return Ok(head);
        }
        bail!("datadir already holds another chain (head {})", head.number);
    }
    let started = Instant::now();
    let (root, via) = match root {
        Some(r) => (r, None),
        None => {
            tracing::info!(number, %hash, "waiting for a snapshot announcement of the checkpoint");
            loop {
                let (via, data) = storage.recv().await.context("network stopped")?;
                if let Some(StorageMsg::Snapshot(a)) = StorageMsg::decode(&data)
                    && a.number == number
                    && a.hash.as_slice() == hash.as_slice()
                {
                    break (a.root, Some(via));
                }
            }
        }
    };
    let peers: Vec<PeerId> = via.into_iter().collect();
    let snap = SnapshotRoot::decode(&get_or_fetch(chain, net, &[root], &peers).await?[&root])?;
    if snap.number != number || snap.hash.as_slice() != hash.as_slice() {
        bail!("snapshot {root} is of block {}, not the checkpoint", snap.number);
    }
    let parts = Chain::snapshot_parts(&snap);
    tracing::info!(number, chunks = parts.len(), "fetching state snapshot");
    let got = get_or_fetch(chain, net, &parts, &peers).await?;
    let env = Envelope::decode(&got[&snap.envelope])?;
    let mut block_parts = vec![env.header];
    block_parts.extend(env.chunks.iter().copied());
    get_or_fetch(chain, net, &block_parts, &peers).await?;
    // Ancestors back to the backfill limit (and the envelope just below it).
    let lower = chain.backfill_from(number);
    let mut parent = env.parent;
    while let Some(p) = parent {
        let e = Envelope::decode(&get_or_fetch(chain, net, &[p], &peers).await?[&p])?;
        if e.height < lower || e.height == 0 {
            break;
        }
        get_or_fetch(chain, net, &[e.header], &peers).await?;
        parent = e.parent;
    }
    let c = chain.clone();
    let header = tokio::task::spawn_blocking(move || c.import_checkpoint(&root, &hash)).await??;
    tracing::info!(
        number,
        secs = started.elapsed().as_secs_f32(),
        "checkpoint sync complete; following the chain from here"
    );
    Ok(header)
}

/// Parses `--checkpoint <number>:<hash>`.
pub fn parse_checkpoint(s: &str) -> Result<(u64, B256)> {
    let (n, h) = s.split_once(':').context("expected <number>:<hash>")?;
    Ok((n.parse()?, h.parse()?))
}
