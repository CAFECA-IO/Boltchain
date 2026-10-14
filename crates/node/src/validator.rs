//! Validator: runs the consensus engine of the current epoch against the chain, the transaction
//! pool and the network (ADR 0005, 0006).
//!
//! Data-availability rule: a validator only votes for a proposal after it holds every part of the
//! block (fetched over Bitswap and written to its blockstore) and has executed it on top of the
//! parent and matched the header. A QC therefore also certifies that more than 2/3 of the seats
//! hold the data.
//!
//! Epochs: the committee of each epoch is read from `ConsensusRegistry` (written one epoch ahead).
//! One node may hold several validator keys; every key on the committee signs through the same
//! engine. When the epoch's last block is final the engine reports it with its proof; the node
//! stores the proof (the next epoch's first block carries it) and starts the next epoch's engine.
//!
//! Mining phase (ADR 0007): until a committee exists the node follows the mined chain (and may
//! mine itself). In phase B each epoch's committee runs the same engine over the mined chain and
//! finalizes checkpoints (see [`crate::checkpoint`]); mining goes on. Under PoS the committee
//! produces the blocks.
//!
//! The first committee epoch starts from a block nobody certified as its anchor, like epoch 0
//! starts from genesis: the last block before phase B (or before PoS, if phase B never ran). If a
//! heavier mined branch replaces it before the committee certified anything, the engine restarts
//! on the new anchor without ever signing again in a round it already used. When phase B ran, it
//! finalizes the terminal block, and the first PoS block carries that proof.

use crate::keys;
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes};
use anyhow::{Context, Result, bail};
use bolt_chain::{Chain, ChainError, EXTRA_DATA_LEN};
use bolt_consensus::{
    Action, BlockInfo, BlsScheme, Cert, CommitProof, Config, Engine, Message, Persisted, Proposal,
    Qc, Tc, ValidatorIndex, ValidatorSet, decode_cert, encode_cert, randao_msg,
};
use bolt_ipld::{Envelope, decode_block, verify};
use bolt_net::{Announce, NetEvent, NetHandle};
use bolt_primitives::bls::{self, BlsSecretKey, BlsSignature};
use bolt_rpc::HeadState;
use bolt_store::StateView;
use bolt_sync::{FinalityCheck, Follower, Verdict};
use bolt_system::queries::{self, EpochCommittee};
use bolt_txpool::TxPool;
use libp2p::PeerId;
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;

/// How often a node re-publishes its head while that head is a mined block.
const REANNOUNCE: Duration = Duration::from_secs(4);

/// How often a node whose epoch ended retries entering the next one.
const EPOCH_RETRY: Duration = Duration::from_secs(5);

/// Validator options.
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Minimum time between a block and its child (the slot), in milliseconds.
    pub slot_ms: u64,
    /// Base round timeout in milliseconds.
    pub base_timeout_ms: u64,
    /// Directory for consensus safety state, epoch proofs and equivocation evidence.
    pub state_dir: PathBuf,
}

/// Block an epoch starts from: genesis for epoch 0, else the previous epoch's last block (which
/// must be final locally).
pub fn epoch_anchor(chain: &Chain, epoch: u64) -> Result<Option<BlockInfo>> {
    let height = if epoch == 0 { 0 } else { chain.rules().epoch_end(epoch - 1) };
    let r = chain.store().reader()?;
    Ok(r.header(height)?.map(|h: Header| BlockInfo {
        hash: h.hash_slow(),
        parent: h.parent_hash,
        round: 0,
        height,
    }))
}

/// Whether `qc` is the anchor certificate of a chain start: genesis (epoch 0), or the uncertified
/// last block before the first committee epoch (phase B, or PoS if phase B never ran). The block
/// after it carries no certificate.
pub fn is_start_anchor(chain: &Chain, qc: &Qc<BlsScheme>) -> bool {
    if qc.is_genesis() {
        return true;
    }
    if !qc.is_anchor() {
        return false;
    }
    let Ok(phase) = chain.phase() else { return false };
    match phase.checkpoint_epoch {
        Some(b) if b > 0 => qc.epoch == b && qc.height == chain.rules().epoch_end(b - 1),
        _ => false,
    }
}

/// What the committee of an epoch does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Finalizes mined blocks (phase B).
    Checkpoints,
    /// Produces the blocks (PoS).
    Blocks,
}

/// What the committee of `epoch` does, if there is one.
pub fn mode_of(chain: &Chain, epoch: u64) -> Result<Option<Mode>> {
    let phase = chain.phase()?;
    if phase.pos_epoch.is_some_and(|p| epoch >= p) {
        return Ok(Some(Mode::Blocks));
    }
    Ok(phase.is_checkpoint_epoch(epoch).then_some(Mode::Checkpoints))
}

/// The committee epoch this node should run now, if any: under PoS the one after the head; in
/// phase B the one after the last finalized checkpoint (the first one once its uncertified anchor
/// is buried deep enough).
pub fn next_consensus_epoch(chain: &Chain) -> Result<Option<u64>> {
    let phase = chain.phase()?;
    let rules = chain.rules();
    let head = chain.head()?.number;
    let fin = chain.finalized()?.map(|(n, _)| n).unwrap_or(0);
    if phase.is_pos(rules, head + 1) {
        let terminal = phase.terminal_height(rules).unwrap_or(0);
        // With phase B the PoS epoch starts from the finalized terminal block.
        if !phase.terminal_is_checkpointed() || head > terminal || fin >= terminal {
            return Ok(Some(rules.epoch_of(head + 1)));
        }
    }
    let Some(b) = phase.checkpoint_epoch else { return Ok(None) };
    if b == 0 {
        return Ok(Some(rules.epoch_of(head + 1)));
    }
    let start = rules.epoch_end(b - 1);
    if fin >= start {
        return Ok(Some(rules.epoch_of(fin + 1)));
    }
    let buried = head >= start + crate::checkpoint::required_depth(chain, start);
    Ok(buried.then_some(b))
}

/// The committee of `epoch` from local state, if known yet.
pub fn committee_of(chain: &Chain, epoch: u64) -> Result<Option<EpochCommittee>> {
    let r = chain.store().reader()?;
    Ok(queries::committee_at(&StateView::latest(&r), chain.config().chain_id, epoch)?)
}

fn validator_set(c: &EpochCommittee) -> ValidatorSet {
    ValidatorSet::from_seats(
        c.committee.members.len(),
        c.committee.seats.iter().map(|s| *s as ValidatorIndex).collect(),
    )
}

/// Verifies finality proofs against the committees in local state.
#[derive(Debug, Clone)]
pub struct Finality {
    chain: Arc<Chain>,
}

impl Finality {
    /// For `chain`.
    pub fn new(chain: Arc<Chain>) -> Self {
        Self { chain }
    }
}

impl FinalityCheck for Finality {
    fn check(&self, height: u64, hash: &B256, proof: &[u8]) -> Verdict {
        let Ok(p) = serde_ipld_dagcbor::from_slice::<CommitProof<BlsScheme>>(proof) else {
            return Verdict::NotFinal;
        };
        let rules = *self.chain.rules();
        let epoch = p.qc.epoch;
        if rules.epoch_of(height) != epoch {
            return Verdict::NotFinal;
        }
        let (Ok(Some(c)), Ok(Some(anchor))) =
            (committee_of(&self.chain, epoch), epoch_anchor(&self.chain, epoch))
        else {
            return Verdict::Unknown;
        };
        let scheme = BlsScheme::new(c.pubkeys.clone(), &[]);
        let ok = p.verify(&scheme, &validator_set(&c), self.chain.config().chain_id, &anchor.hash)
            == Some(*hash)
            && p.committed_height == height
            && (p.nil_rounds.is_empty() || height == rules.epoch_end(epoch));
        if ok { Verdict::Final } else { Verdict::NotFinal }
    }

    fn parent_proof(&self, cert: &[u8]) -> Option<Vec<u8>> {
        match decode_cert::<BlsScheme>(cert)? {
            Cert::Epoch(p) => serde_ipld_dagcbor::to_vec(&p).ok(),
            Cert::Qc(_) => None,
        }
    }

    fn is_epoch_start(&self, height: u64) -> bool {
        self.chain.rules().is_epoch_start(height)
    }
}

struct Built {
    block: BlockInfo,
    qc: Qc<BlsScheme>,
    tc: Option<Tc<BlsScheme>>,
    payload: Vec<u8>,
    epoch: u64,
}

enum Internal {
    /// The catch-up worker imported blocks.
    Imported,
    Timer(u64, u64),
    Validated(u64, B256, bool),
    Built(Box<Built>),
    Fetched(u64, BlockInfo),
}

/// Everything about the epoch being run.
struct EpochCtx {
    epoch: u64,
    engine: Engine<BlsScheme>,
    committee: EpochCommittee,
    end: u64,
    mode: Mode,
    /// Seats this node signs for.
    me: Vec<ValidatorIndex>,
    /// Last round this node had voted in when it (re)started this epoch: older messages signed
    /// with our keys may be our own from before a restart.
    resumed_round: u64,
}

/// Doppelganger protection: a validator key running on two nodes double-signs sooner or later
/// and is slashed. Every consensus message this node publishes is remembered; if a valid vote or
/// timeout signed by one of our seats arrives that we did not send (in a round after our restart
/// point), another node holds the same key, and this node stops signing with that validator key
/// (its other keys keep working) until restarted.
#[derive(Default)]
struct Doppelganger {
    sent: std::collections::HashSet<B256>,
    /// Validator ids whose keys were seen in use elsewhere.
    tripped: std::collections::HashSet<u32>,
}

impl Doppelganger {
    /// Whether `msg` is signed with a key that must no longer sign.
    fn blocks(&self, ctx: &EpochCtx, msg: &Message<BlsScheme>) -> bool {
        if self.tripped.is_empty() {
            return false;
        }
        let seat = match msg {
            Message::Proposal(p) => p.proposer,
            Message::Vote(v) => v.signer,
            Message::Timeout(t) => t.signer,
        };
        ctx.committee
            .committee
            .members
            .get(seat as usize)
            .is_some_and(|id| self.tripped.contains(id))
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn round_of(extra: &Bytes) -> Option<u64> {
    (extra.len() == EXTRA_DATA_LEN)
        .then(|| u64::from_be_bytes(extra[..8].try_into().unwrap_or_default()))
}

/// Everything the validator task needs.
pub struct Validator {
    /// Chain.
    pub chain: Arc<Chain>,
    /// Transaction pool.
    pub pool: Arc<TxPool>,
    /// Network.
    pub net: NetHandle,
    /// Validator keys held by this node.
    pub keys: Vec<BlsSecretKey>,
    /// Options.
    pub cfg: ValidatorConfig,
    /// Mine while the chain is in its mining phase.
    pub miner: Option<crate::miner::MinerConfig>,
}

impl std::fmt::Debug for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Validator").field("keys", &self.keys.len()).finish()
    }
}

/// Votes seen per (epoch, round, signer), for equivocation detection.
type SeenVotes = HashMap<(u64, u64, u16), (B256, BlsSignature)>;

impl Validator {
    fn state_path(&self) -> PathBuf {
        self.cfg.state_dir.join("consensus-state.json")
    }

    fn proof_path(&self, epoch: u64) -> PathBuf {
        self.cfg.state_dir.join("epoch-proofs").join(format!("{epoch}.cbor"))
    }

    /// The envelope certificate for a block whose parent is certified by `qc`.
    fn cert_bytes(&self, qc: &Qc<BlsScheme>) -> Option<Vec<u8>> {
        if is_start_anchor(&self.chain, qc) {
            return Some(Vec::new());
        }
        if !qc.is_anchor() {
            return Some(encode_cert(&Cert::Qc(qc.clone())));
        }
        // First block of an epoch: the proof that the anchor is final.
        if let Some(b) = load_proof_at(&self.proof_path(qc.epoch - 1)) {
            return Some(b);
        }
        // Someone else already built it (we joined late): take it from the chain.
        let r = self.chain.store().reader().ok()?;
        let root = r.envelope_root(qc.height + 1).ok()??;
        let env = Envelope::decode(&r.ipld(&root).ok()??).ok()?;
        Some(env.qc)
    }

    fn save_proof(&self, epoch: u64, proof: &CommitProof<BlsScheme>) {
        save_proof_at(&self.proof_path(epoch), epoch, proof);
    }

    fn enter_epoch(&self, epoch: u64) -> Result<EpochCtx> {
        let mode = mode_of(&self.chain, epoch)?.context("no committee for this epoch")?;
        let anchor = epoch_anchor(&self.chain, epoch)?.context("epoch anchor not final yet")?;
        let committee = committee_of(&self.chain, epoch)?.context("committee not in state yet")?;
        let scheme = BlsScheme::new(committee.pubkeys.clone(), &self.keys);
        let me = scheme.signers();
        let end = self.chain.rules().epoch_end(epoch);
        // Checkpoint rounds wait for mined blocks: give them a few block intervals.
        let base_timeout_ms = match mode {
            Mode::Blocks => self.cfg.base_timeout_ms,
            Mode::Checkpoints => {
                self.cfg.base_timeout_ms.max(3_000 * self.chain.config().pow.block_seconds)
            }
        };
        let cfg = Config {
            chain_id: self.chain.config().chain_id,
            epoch,
            validators: validator_set(&committee),
            me: me.clone(),
            anchor: anchor.clone(),
            end_height: end,
            base_timeout_ms,
        };
        // A state file that exists but cannot be read must not be ignored: starting over would
        // let this node vote again in rounds it already voted in (equivocation).
        let persisted = match std::fs::read(self.state_path()) {
            Ok(b) => Some(serde_json::from_slice::<Persisted<BlsScheme>>(&b).with_context(|| {
                format!(
                    "consensus state {} is unreadable; restore it from a backup (or, knowing this \
                     node's keys signed nothing in the current epoch, remove it)",
                    self.state_path().display()
                )
            })?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).context("reading consensus state"),
        };
        let resumed_round =
            persisted.as_ref().filter(|p| p.epoch == epoch).map(|p| p.last_voted).unwrap_or(0);
        let engine = match persisted {
            // Saved for another terminal block (a mined reorganisation replaced it before
            // anything was certified): start over on this anchor, above every used round.
            Some(p)
                if p.epoch == epoch
                    && p.high_qc.is_anchor()
                    && p.committed.height == anchor.height
                    && p.committed.hash != anchor.hash =>
            {
                tracing::warn!(
                    epoch,
                    last_voted = p.last_voted,
                    "anchor changed; restarting epoch"
                );
                Engine::reanchored(cfg, scheme, p.last_voted)
            }
            Some(p) if p.epoch == epoch => {
                // Blocks the engine knows above the last final one were only in memory; the
                // highest certificate usually names one of them, and every leader must build on
                // it. Execute them again from the blockstore (all nodes may have restarted).
                let mut wanted: Vec<B256> = p.blocks.iter().map(|b| b.hash).collect();
                wanted.extend([p.high_qc.block, p.committed.hash]);
                match self.chain.restore_pending(&wanted) {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(epoch, blocks = n, "restored pending blocks"),
                    Err(e) => tracing::warn!(epoch, "could not restore pending blocks: {e}"),
                }
                tracing::info!(
                    epoch,
                    committed = p.committed.height,
                    last_voted = p.last_voted,
                    "resuming consensus state"
                );
                Engine::resume(cfg, scheme, p)
            }
            _ => Engine::new(cfg, scheme),
        };
        tracing::info!(
            epoch,
            members = committee.committee.members.len(),
            seats = committee.committee.seats.len(),
            local = me.len(),
            start = anchor.height + 1,
            end,
            ?mode,
            "epoch starting"
        );
        Ok(EpochCtx { epoch, engine, committee, end, mode, me, resumed_round })
    }

    /// Height up to which the current epoch's work is final: the head under PoS, the last
    /// finalized checkpoint in phase B.
    fn progress(&self, mode: Mode) -> u64 {
        match mode {
            Mode::Blocks => self.chain.head().map(|h| h.number).unwrap_or(0),
            Mode::Checkpoints => self.chain.finalized().ok().flatten().map(|(n, _)| n).unwrap_or(0),
        }
    }

    /// Adds a transaction a peer gossiped (invalid or known ones are ignored).
    fn admit_gossiped(&self, raw: &[u8]) {
        if let Ok(r) = self.chain.store().reader() {
            let _ = self.pool.add_gossiped(raw, &HeadState(&r));
        }
    }

    /// Runs until the network event stream ends.
    pub async fn run(self, mut events: mpsc::Receiver<NetEvent>) -> Result<()> {
        std::fs::create_dir_all(&self.cfg.state_dir)?;
        // Transactions this node admits (RPC, forwarding) are gossiped so every block producer
        // sees them.
        let net = self.net.clone();
        self.pool.on_admit(Box::new(move |raw| net.gossip_tx(raw.to_vec())));
        let (itx, mut irx) = mpsc::unbounded_channel::<Internal>();
        let catch_up = self.spawn_catch_up(itx.clone());
        let mut sources: HashMap<B256, PeerId> = HashMap::new();
        let mut rounds: HashMap<B256, u64> = HashMap::new();
        let mut future: VecDeque<Message<BlsScheme>> = VecDeque::new();
        let orphans = Orphans::default();
        let cert_slot: crate::miner::CertSlot = Default::default();
        // Mines until PoS starts (it stops by itself then).
        let miner = self.miner.clone().map(|cfg| {
            tokio::spawn(crate::miner::run(
                self.chain.clone(),
                self.pool.clone(),
                self.net.clone(),
                cfg,
                cert_slot.clone(),
            ))
        });
        let _abort_miner = AbortOnDrop(miner);
        let Some(first) = self.mining_phase(&mut events, &mut irx, &catch_up, &mut future).await?
        else {
            return Ok(());
        };
        let mut ctx = self.enter_epoch(first)?;
        let mut seen: SeenVotes = HashMap::new();
        let mut dg = Doppelganger::default();
        let mut actions = ctx.engine.start();
        actions.extend(self.replay(&mut ctx, &mut future));
        let mut reannounce = tokio::time::interval(REANNOUNCE);
        // Entering the next epoch can fail for a passing reason (no file descriptor left, say);
        // nothing else would ask again once the finished epoch's engine is idle.
        let mut epoch_retry = tokio::time::interval(EPOCH_RETRY);
        epoch_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut logged = (0, 0);
        loop {
            self.handle(&mut ctx, actions, &itx, &sources, &rounds, &mut future, &mut dg, &orphans)
                .await;
            let after = (ctx.engine.round(), ctx.engine.high_qc().round);
            if after != logged {
                logged = after;
                bolt_primitives::metrics::CONSENSUS_ROUND.set(after.0);
                tracing::debug!(
                    round = after.0,
                    high_qc = after.1,
                    committed = ctx.engine.committed().height,
                    leader = ctx.engine.validators().leader(after.0),
                    "consensus round"
                );
            }
            if ctx.mode == Mode::Checkpoints {
                // Mined blocks carry the latest checkpoint QC: it pays its signers.
                let qc = ctx.engine.high_qc();
                if !qc.is_anchor() {
                    *cert_slot.lock() = Some((qc.epoch, encode_cert(&Cert::Qc(qc.clone()))));
                }
            }
            actions = tokio::select! {
                _ = epoch_retry.tick() => self.catch_up_epochs(&mut ctx, &mut future),
                _ = reannounce.tick() => {
                    // Until the committee certified a block, keep the terminal block visible.
                    self.reannounce_mined_head().await;
                    vec![]
                }
                ev = events.recv() => match ev {
                    None => break,
                    Some(NetEvent::Consensus { via, data }) => match bolt_consensus::decode::<BlsScheme>(&data) {
                        Some(msg) => {
                            self.watch_equivocation(&ctx, &msg, &mut seen);
                            self.watch_doppelganger(&ctx, &msg, &data, &mut dg);
                            match &msg {
                                Message::Proposal(p) => tracing::debug!(
                                    round = p.block.round, height = p.block.height,
                                    proposer = p.proposer, qc = p.qc.round,
                                    tc = p.tc.as_ref().map(|t| t.round), local = ctx.engine.round(),
                                    "proposal received"
                                ),
                                Message::Vote(v) => tracing::debug!(
                                    round = v.round, height = v.height, signer = v.signer,
                                    local = ctx.engine.round(), "vote received"
                                ),
                                Message::Timeout(t) => tracing::debug!(
                                    round = t.round, high_qc = t.high_qc.round, signer = t.signer,
                                    local = ctx.engine.round(), "timeout received"
                                ),
                            }
                            if let Message::Proposal(p) = &msg {
                                sources.insert(p.block.hash, via);
                                rounds.insert(p.block.hash, p.block.round);
                                if sources.len() > 256 {
                                    sources.clear();
                                    rounds.clear();
                                }
                            }
                            if msg.epoch() == ctx.epoch {
                                ctx.engine.on_message(msg)
                            } else {
                                if msg.epoch() > ctx.epoch {
                                    if future.len() >= 4096 {
                                        future.pop_front();
                                    }
                                    future.push_back(msg);
                                }
                                vec![]
                            }
                        }
                        None => vec![],
                    },
                    Some(NetEvent::Announce { via, announce }) => {
                        // Catch-up path for blocks finalized while we were behind, off the main
                        // loop so consensus keeps up while importing.
                        // In phase B every mined block matters (side branches, finality proofs).
                        let head = self.chain.head().map(|h| h.number).unwrap_or(0);
                        if announce.height > head || ctx.mode == Mode::Checkpoints {
                            let _ = catch_up.try_send((via, announce));
                        }
                        vec![]
                    }
                    Some(NetEvent::Tx { raw, reply }) => {
                        let r = self.chain.store().reader().ok();
                        let res = match &r {
                            Some(r) => self.pool.add_raw(&raw, &HeadState(r)).map_err(|e| e.to_string()),
                            None => Err("store unavailable".into()),
                        };
                        let _ = reply.send(res);
                        vec![]
                    }
                    Some(NetEvent::GossipTx { raw }) => {
                        self.admit_gossiped(&raw);
                        vec![]
                    }
                    Some(NetEvent::Connected(_) | NetEvent::Storage { .. }) => vec![],
                },
                i = irx.recv() => match i {
                    None => break,
                    Some(Internal::Imported) => {
                        let mut out = self.reanchor(&mut ctx, &mut future);
                        out.extend(self.catch_up_epochs(&mut ctx, &mut future));
                        out
                    }
                    Some(Internal::Timer(e, r)) if e == ctx.epoch => ctx.engine.on_timeout(r),
                    Some(Internal::Validated(e, h, ok)) if e == ctx.epoch => ctx.engine.on_validated(h, ok),
                    Some(Internal::Built(b)) if b.epoch == ctx.epoch => {
                        let Built { block, qc, tc, payload, .. } = *b;
                        let (round, height) = (block.round, block.height);
                        let out = ctx.engine.on_proposed(block, qc, tc, payload);
                        tracing::debug!(
                            round, height, local = ctx.engine.round(), sent = !out.is_empty(),
                            "own proposal built"
                        );
                        out
                    }
                    Some(Internal::Fetched(e, b)) if e == ctx.epoch => ctx.engine.on_block(b),
                    Some(_) => vec![], // from an epoch we left
                },
            };
        }
        Ok(())
    }

    /// Until a committee epoch can run: follow (and optionally mine) the mined chain, keep
    /// transactions, buffer early consensus messages. Returns the epoch to run, or `None` if the
    /// network stopped.
    async fn mining_phase(
        &self,
        events: &mut mpsc::Receiver<NetEvent>,
        irx: &mut mpsc::UnboundedReceiver<Internal>,
        catch_up: &mpsc::Sender<(PeerId, Announce)>,
        future: &mut VecDeque<Message<BlsScheme>>,
    ) -> Result<Option<u64>> {
        if let Some(e) = next_consensus_epoch(&self.chain)? {
            return Ok(Some(e));
        }
        tracing::info!(head = self.chain.head()?.number, "mining phase: following mined blocks");
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut last_announce = std::time::Instant::now();
        let ready = loop {
            if last_announce.elapsed() > REANNOUNCE {
                self.reannounce_mined_head().await;
                last_announce = std::time::Instant::now();
            }
            if let Some(e) = next_consensus_epoch(&self.chain)? {
                break Some(e);
            }
            tokio::select! {
                ev = events.recv() => match ev {
                    None => break None,
                    Some(NetEvent::Consensus { data, .. }) => {
                        if let Some(msg) = bolt_consensus::decode::<BlsScheme>(&data) {
                            if future.len() >= 4096 {
                                future.pop_front();
                            }
                            future.push_back(msg);
                        }
                    }
                    Some(NetEvent::Announce { via, announce }) => {
                        let _ = catch_up.try_send((via, announce));
                    }
                    Some(NetEvent::Tx { raw, reply }) => {
                        let r = self.chain.store().reader().ok();
                        let res = match &r {
                            Some(r) => self.pool.add_raw(&raw, &HeadState(r)).map_err(|e| e.to_string()),
                            None => Err("store unavailable".into()),
                        };
                        let _ = reply.send(res);
                    }
                    Some(NetEvent::GossipTx { raw }) => self.admit_gossiped(&raw),
                    Some(NetEvent::Connected(_) | NetEvent::Storage { .. }) => {}
                },
                _ = irx.recv() => {
                    if let Ok(r) = self.chain.store().reader() {
                        self.pool.on_new_block(&HeadState(&r));
                    }
                }
                _ = tick.tick() => {}
            }
        };
        if let Some(e) = ready {
            let phase = self.chain.phase()?;
            tracing::info!(
                epoch = e,
                checkpoints_from = ?phase.checkpoint_epoch,
                pos_from = ?phase.pos_epoch,
                terminal = ?phase.terminal_height(self.chain.rules()),
                "a committee takes over"
            );
        }
        Ok(ready)
    }

    /// Re-publishes the head while it is a mined block, so nodes that missed a block (or sit on a
    /// lighter branch) converge; this matters most at the terminal block, after which nothing is
    /// mined any more.
    async fn reannounce_mined_head(&self) {
        let Ok(head) = self.chain.head() else { return };
        if head.number == 0 || head.difficulty.is_zero() {
            return;
        }
        if let Some(a) = bolt_sync::announce_stored(&self.chain, head.number, Vec::new()) {
            let _ = self.net.publish(a).await;
        }
    }

    /// First PoS epoch: if a mined reorganisation replaced the terminal block before anything
    /// was certified, restart the engine on the new anchor (never reusing a round).
    fn reanchor(
        &self,
        ctx: &mut EpochCtx,
        future: &mut VecDeque<Message<BlsScheme>>,
    ) -> Vec<Action<BlsScheme>> {
        let Ok(Some(anchor)) = epoch_anchor(&self.chain, ctx.epoch) else { return vec![] };
        let current = ctx.engine.config().anchor.clone();
        if anchor.hash == current.hash
            || ctx.engine.committed().height != current.height
            || !ctx.engine.high_qc().is_anchor()
        {
            return vec![];
        }
        tracing::warn!(epoch = ctx.epoch, old = %current.hash, new = %anchor.hash, "terminal block replaced; restarting the epoch");
        let _ = self.persist(&ctx.engine);
        match self.enter_epoch(ctx.epoch) {
            Ok(next) => {
                *ctx = next;
                let mut out = ctx.engine.start();
                out.extend(self.replay(ctx, future));
                out
            }
            Err(e) => {
                tracing::warn!("cannot restart epoch {}: {e:#}", ctx.epoch);
                vec![]
            }
        }
    }

    /// Worker importing announced final blocks (with proofs) one announcement at a time.
    fn spawn_catch_up(
        &self,
        itx: mpsc::UnboundedSender<Internal>,
    ) -> mpsc::Sender<(PeerId, Announce)> {
        let (tx, mut rx) = mpsc::channel::<(PeerId, Announce)>(16);
        let follower = Follower::with_finality(
            self.chain.clone(),
            self.net.clone(),
            Arc::new(Finality::new(self.chain.clone())),
        );
        let (chain, dir) = (self.chain.clone(), self.cfg.state_dir.clone());
        tokio::spawn(async move {
            while let Some((via, a)) = rx.recv().await {
                let (height, proof) = (a.height, a.proof.clone());
                match follower.on_announce(via, a).await {
                    Ok(_) => {
                        // The last block of an epoch comes with the next epoch's anchor proof.
                        let rules = *chain.rules();
                        let epoch = rules.epoch_of(height);
                        if height == rules.epoch_end(epoch)
                            && let Ok(p) =
                                serde_ipld_dagcbor::from_slice::<CommitProof<BlsScheme>>(&proof)
                        {
                            let path = dir.join("epoch-proofs").join(format!("{epoch}.cbor"));
                            save_proof_at(&path, epoch, &p);
                        }
                        let _ = itx.send(Internal::Imported);
                    }
                    Err(e) => tracing::debug!("catch-up import skipped: {e}"),
                }
            }
        });
        tx
    }

    /// Moves to later epochs if the chain (imported through the catch-up path) passed the current
    /// one's end. Returns the new engine's start actions.
    fn catch_up_epochs(
        &self,
        ctx: &mut EpochCtx,
        future: &mut VecDeque<Message<BlsScheme>>,
    ) -> Vec<Action<BlsScheme>> {
        let mut out = Vec::new();
        loop {
            if self.progress(ctx.mode) < ctx.end {
                return out;
            }
            match self.enter_epoch(ctx.epoch + 1) {
                Ok(next) => {
                    *ctx = next;
                    out = ctx.engine.start();
                    out.extend(self.replay(ctx, future));
                }
                Err(e) => {
                    tracing::warn!("cannot enter epoch {}: {e:#}", ctx.epoch + 1);
                    return out;
                }
            }
        }
    }

    fn replay(
        &self,
        ctx: &mut EpochCtx,
        future: &mut VecDeque<Message<BlsScheme>>,
    ) -> Vec<Action<BlsScheme>> {
        let mut out = Vec::new();
        let msgs: Vec<_> = future.drain(..).collect();
        for m in msgs {
            if m.epoch() == ctx.epoch {
                out.extend(ctx.engine.on_message(m));
            } else if m.epoch() > ctx.epoch {
                future.push_back(m);
            }
        }
        out
    }

    /// A valid vote or timeout from one of our seats that this node did not send: the same key
    /// runs elsewhere. Trips [`Doppelganger`] so this node stops signing.
    fn watch_doppelganger(
        &self,
        ctx: &EpochCtx,
        msg: &Message<BlsScheme>,
        data: &[u8],
        dg: &mut Doppelganger,
    ) {
        if msg.epoch() != ctx.epoch {
            return;
        }
        let chain_id = self.chain.config().chain_id;
        let (signer, round, signed, sig) = match msg {
            Message::Vote(v) => (
                v.signer,
                v.round,
                bolt_consensus::vote_msg(chain_id, v.epoch, v.round, &v.block),
                &v.sig,
            ),
            Message::Timeout(t) => (
                t.signer,
                t.round,
                bolt_consensus::timeout_msg(chain_id, t.epoch, t.round, t.high_qc.round),
                &t.sig,
            ),
            Message::Proposal(_) => return,
        };
        if !ctx.me.contains(&signer)
            || round <= ctx.resumed_round
            || dg.sent.contains(&alloy_primitives::keccak256(data))
        {
            return;
        }
        let Some(pk) = ctx.committee.pubkeys.get(signer as usize) else { return };
        if !bls::verify(pk, &signed, sig) {
            return;
        }
        let Some(&id) = ctx.committee.committee.members.get(signer as usize) else { return };
        if !dg.tripped.insert(id) {
            return;
        }
        bolt_primitives::metrics::DOPPELGANGER.set(dg.tripped.len() as u64);
        tracing::error!(
            validator = id,
            epoch = ctx.epoch,
            round,
            "another node is signing with this validator key; stopped signing with it to avoid \
             being slashed. Stop the other instance, then restart this node"
        );
    }

    /// Two votes by one signer in the same epoch and round for different blocks: slashable.
    /// Writes ready-to-send `ConsensusRegistry.submitEvidence` calldata to `evidence/`.
    fn watch_equivocation(&self, ctx: &EpochCtx, msg: &Message<BlsScheme>, seen: &mut SeenVotes) {
        let Message::Vote(v) = msg else { return };
        if v.epoch != ctx.epoch {
            return;
        }
        let key = (v.epoch, v.round, v.signer);
        match seen.get(&key) {
            None => {
                if seen.len() > 100_000 {
                    seen.clear();
                }
                seen.insert(key, (v.block, v.sig));
            }
            Some((block, sig)) if *block != v.block => {
                let Some(pk) = ctx.committee.pubkeys.get(v.signer as usize) else { return };
                let chain_id = self.chain.config().chain_id;
                let (ma, mb) = (
                    bolt_consensus::vote_msg(chain_id, v.epoch, v.round, block),
                    bolt_consensus::vote_msg(chain_id, v.epoch, v.round, &v.block),
                );
                if !bls::verify(pk, &ma, sig) || !bls::verify(pk, &mb, &v.sig) {
                    return;
                }
                let id = ctx.committee.committee.members[v.signer as usize];
                tracing::error!(
                    validator = id,
                    epoch = v.epoch,
                    round = v.round,
                    "equivocation: two votes in one round"
                );
                if let Some(data) =
                    bolt_system::evidence::submit_evidence_calldata(id, pk, &ma, sig, &mb, &v.sig)
                {
                    let dir = self.cfg.state_dir.join("evidence");
                    let _ = std::fs::create_dir_all(&dir);
                    let file = dir.join(format!("{}-{}-{id}.json", v.epoch, v.round));
                    let json = serde_json::json!({
                        "to": bolt_system::addresses::CONSENSUS,
                        "data": data,
                        "validator": id,
                        "epoch": v.epoch,
                        "round": v.round,
                    });
                    let _ =
                        std::fs::write(file, serde_json::to_vec_pretty(&json).unwrap_or_default());
                }
            }
            Some(_) => {}
        }
    }

    /// Writes the engine's safety state; false if it did not reach the disk.
    fn persist(&self, engine: &Engine<BlsScheme>) -> bool {
        let bytes = serde_json::to_vec(&engine.persisted()).expect("state serializes");
        let path = self.state_path();
        match write_durable(&path, &bytes) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!("could not persist consensus state: {e}");
                false
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle(
        &self,
        ctx: &mut EpochCtx,
        actions: Vec<Action<BlsScheme>>,
        itx: &mpsc::UnboundedSender<Internal>,
        sources: &HashMap<B256, PeerId>,
        rounds: &HashMap<B256, u64>,
        future: &mut VecDeque<Message<BlsScheme>>,
        dg: &mut Doppelganger,
        orphans: &Orphans,
    ) {
        let mut queue: VecDeque<Action<BlsScheme>> = actions.into();
        while !queue.is_empty() {
            // Safety state hits the disk before any vote or timeout leaves this node. If it
            // cannot (disk full, out of file descriptors), they are not sent: after a restart
            // the node could otherwise sign again in a round it already signed in. The timer
            // stays armed, so it retries once writing works again.
            let mut unsaved = false;
            if queue.iter().any(|a| {
                matches!(
                    a,
                    Action::SendTo(..)
                        | Action::Broadcast(Message::Timeout(_))
                        | Action::Broadcast(Message::Vote(_))
                        | Action::Commit { .. }
                )
            }) {
                unsaved = !self.persist(&ctx.engine);
            }
            let batch: Vec<_> = queue.drain(..).collect();
            for a in batch {
                match a {
                    Action::Broadcast(Message::Vote(_) | Message::Timeout(_))
                    | Action::SendTo(..)
                        if unsaved =>
                    {
                        tracing::warn!("consensus state not saved; withholding a vote or timeout");
                    }
                    Action::Broadcast(m) | Action::SendTo(_, m) => {
                        if dg.blocks(ctx, &m) {
                            continue;
                        }
                        let data = bolt_consensus::encode(&m);
                        if dg.sent.len() > 50_000 {
                            dg.sent.clear();
                        }
                        dg.sent.insert(alloy_primitives::keccak256(&data));
                        let _ = self.net.publish_consensus(data).await;
                    }
                    Action::ScheduleTimeout { round, after_ms } => {
                        let (itx, epoch) = (itx.clone(), ctx.epoch);
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(after_ms)).await;
                            let _ = itx.send(Internal::Timer(epoch, round));
                        });
                    }
                    Action::Validate(p) => {
                        let (chain, net, itx) = (self.chain.clone(), self.net.clone(), itx.clone());
                        let via = sources.get(&p.block.hash).copied();
                        let (epoch, keys) = (ctx.epoch, ctx.committee.pubkeys.clone());
                        let mode = ctx.mode;
                        let orphans = orphans.clone();
                        tokio::spawn(async move {
                            let hash = p.block.hash;
                            let res = match mode {
                                Mode::Blocks => {
                                    validate_with_ancestors(&chain, &net, &p, via, &keys, &orphans)
                                        .await
                                }
                                Mode::Checkpoints => crate::checkpoint::validate(&chain, &p).await,
                            };
                            let ok = match res {
                                Ok(()) => true,
                                Err(e) => {
                                    bolt_primitives::metrics::PROPOSALS_REJECTED.inc();
                                    tracing::warn!(
                                        round = p.block.round,
                                        height = p.block.height,
                                        "proposal rejected: {e:#}"
                                    );
                                    false
                                }
                            };
                            let _ = itx.send(Internal::Validated(epoch, hash, ok));
                        });
                    }
                    Action::Propose { round, qc, tc } if ctx.mode == Mode::Checkpoints => {
                        let (chain, itx, epoch) = (self.chain.clone(), itx.clone(), ctx.epoch);
                        // Wait for the checkpoint to be buried for most of this round: after
                        // timeouts the round is longer, and giving up at the base timeout would
                        // waste it (rounds then only advanced by timeouts, 8x base each).
                        let deadline = ctx.engine.round_timeout_ms() * 3 / 4;
                        tokio::spawn(async move {
                            match crate::checkpoint::propose(&chain, round, &qc, deadline).await {
                                Ok(block) => {
                                    let b = Built { block, qc, tc, payload: Vec::new(), epoch };
                                    let _ = itx.send(Internal::Built(Box::new(b)));
                                }
                                Err(e) => tracing::debug!(round, "no checkpoint to propose: {e:#}"),
                            }
                        });
                    }
                    Action::Propose { round, qc, tc } => {
                        let Some(cert) = self.cert_bytes(&qc) else {
                            tracing::warn!(
                                round,
                                "no epoch proof for the anchor yet; skipping proposal"
                            );
                            continue;
                        };
                        let leader = ctx.engine.validators().leader(round);
                        let fee_recipient = ctx
                            .committee
                            .fee_recipients
                            .get(leader as usize)
                            .copied()
                            .unwrap_or(Address::ZERO);
                        let Some(sk) = ctx.committee.pubkeys.get(leader as usize).and_then(|pk| {
                            self.keys.iter().find(|k| k.public_key() == *pk).cloned()
                        }) else {
                            continue;
                        };
                        let (chain, pool, itx) =
                            (self.chain.clone(), self.pool.clone(), itx.clone());
                        let (slot, epoch) = (self.cfg.slot_ms, ctx.epoch);
                        tokio::spawn(async move {
                            match propose(&chain, &pool, round, &qc, cert, slot, fee_recipient, &sk)
                                .await
                            {
                                Ok((block, payload)) => {
                                    let b = Built { block, qc, tc, payload, epoch };
                                    let _ = itx.send(Internal::Built(Box::new(b)));
                                }
                                Err(e) => tracing::warn!(round, "could not build proposal: {e:#}"),
                            }
                        });
                    }
                    Action::Commit { blocks, proof } if ctx.mode == Mode::Checkpoints => {
                        self.commit_checkpoint(blocks, proof).await
                    }
                    Action::Commit { blocks, proof } => self.commit(blocks, proof).await,
                    Action::EpochEnd { block, proof } => {
                        tracing::info!(epoch = ctx.epoch, height = block.height, "epoch final");
                        self.save_proof(ctx.epoch, &proof);
                        queue.extend(self.catch_up_epochs(ctx, future));
                    }
                    Action::FetchBlock(hash) => {
                        // Blocks are content-addressed: if we have the header (pending or final) we
                        // can describe it; otherwise the catch-up path brings it with a proof.
                        // Checkpoint rounds are not in mined headers: use the proposal we saw or the
                        // certificate we hold. Failing both (an ancestor certified before this
                        // node restarted), round 0. Such a block is only walked through on the way
                        // back to the last committed block: the two-chain rule needs P.round + 1 ==
                        // B.round, and round 0 could only pair with a round-1 block, whose parent
                        // is the epoch's anchor (already committed).
                        let round_for = |h: &Header| match ctx.mode {
                            Mode::Blocks => round_of(&h.extra_data),
                            Mode::Checkpoints => Some(
                                rounds
                                    .get(&hash)
                                    .copied()
                                    .or_else(|| ctx.engine.certified_round(&hash))
                                    .unwrap_or(0),
                            ),
                        };
                        if let Ok(Some(h)) = self.chain.header_any(&hash)
                            && let Some(round) = round_for(&h)
                        {
                            let b =
                                BlockInfo { hash, parent: h.parent_hash, round, height: h.number };
                            let _ = itx.send(Internal::Fetched(ctx.epoch, b));
                        }
                    }
                }
            }
        }
    }

    /// Phase B: the committed checkpoint (and its ancestors) is final. Publishes it with its
    /// proof so every node stops following branches below it.
    async fn commit_checkpoint(&self, blocks: Vec<BlockInfo>, mut proof: CommitProof<BlsScheme>) {
        let Some(last) = blocks.last().cloned() else { return };
        let chain = self.chain.clone();
        let res =
            tokio::task::spawn_blocking(move || chain.finalize(&last.hash, last.height)).await;
        match res {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::warn!(height = last.height, "cannot finalize checkpoint: {e}");
                return;
            }
            Err(e) => {
                tracing::error!("finalize task failed: {e}");
                return;
            }
        }
        if proof.nil_rounds.is_empty() {
            match self.chain.header_any(&proof.child_qc.block) {
                Ok(Some(h)) => proof.child_header = alloy_rlp::encode(&h),
                _ => return,
            }
        }
        tracing::info!(height = last.height, hash = %last.hash, "checkpoint final");
        let bytes = serde_ipld_dagcbor::to_vec(&proof).expect("proof serializes");
        if let Some(a) = bolt_sync::announce_stored(&self.chain, last.height, bytes) {
            let _ = self.net.publish(a).await;
        }
    }

    async fn commit(&self, blocks: Vec<BlockInfo>, mut proof: CommitProof<BlsScheme>) {
        let chain = self.chain.clone();
        let last = blocks.last().cloned();
        let res = tokio::task::spawn_blocking(move || {
            for b in &blocks {
                let head = chain.head()?;
                if head.number >= b.height {
                    continue; // already imported (e.g. via the catch-up path)
                }
                chain.commit_pending(&b.hash)?;
            }
            anyhow::Ok(())
        })
        .await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!("commit deferred to catch-up: {e:#}");
                return;
            }
            Err(e) => {
                tracing::error!("commit task failed: {e}");
                return;
            }
        }
        if let Ok(r) = self.chain.store().reader() {
            self.pool.on_new_block(&HeadState(&r));
        }
        let Some(last) = last else { return };
        // Publish the final block with its proof, for followers and lagging validators.
        if proof.nil_rounds.is_empty() {
            match self.chain.header_of(&proof.child_qc.block) {
                Ok(Some(h)) => proof.child_header = alloy_rlp::encode(&h),
                _ => return,
            }
        }
        let r = match self.chain.store().reader() {
            Ok(r) => r,
            Err(_) => return,
        };
        let Ok(Some(root)) = r.envelope_root(last.height) else { return };
        let Some(envelope) = r.ipld(&root).ok().flatten() else { return };
        let Ok(env) = Envelope::decode(&envelope) else { return };
        let header = r.ipld(&env.header).ok().flatten().unwrap_or_default();
        let announce = Announce {
            height: last.height,
            root,
            envelope,
            header,
            inline: Vec::new(),
            proof: serde_ipld_dagcbor::to_vec(&proof).expect("proof serializes"),
            at: 0,
        };
        tracing::info!(height = last.height, hash = %last.hash, round = last.round, "finalized");
        let _ = self.net.publish(announce).await;
    }
}

/// Replaces `path` with `bytes` so that after a power cut it holds either the old or the new
/// content, never a truncated file: write a temporary file, flush it to disk, rename it over
/// `path`, flush the directory. Votes are sent only after this returns.
fn write_durable(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Epoch proofs also kept in memory (latest few), so a node whose disk write failed still has
/// the proof its next proposal needs: on 2026-10-11 a validator out of file descriptors could
/// not store it, and as leader of the new epoch's round 2 skipped its proposal.
type ProofCache = parking_lot::Mutex<VecDeque<(PathBuf, Vec<u8>)>>;

fn proof_cache() -> &'static ProofCache {
    static CACHE: std::sync::OnceLock<ProofCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn save_proof_at(path: &std::path::Path, epoch: u64, proof: &CommitProof<BlsScheme>) {
    let bytes = encode_cert(&Cert::Epoch(proof.clone()));
    {
        let mut c = proof_cache().lock();
        c.retain(|(p, _)| p != path);
        c.push_back((path.to_path_buf(), bytes.clone()));
        while c.len() > 8 {
            c.pop_front();
        }
    }
    let _ = std::fs::create_dir_all(path.parent().expect("has parent"));
    if let Err(e) = write_durable(path, &bytes) {
        tracing::error!(epoch, "could not store epoch proof (kept in memory): {e}");
    }
}

/// An epoch proof saved by [`save_proof_at`]: from memory, else from disk.
fn load_proof_at(path: &std::path::Path) -> Option<Vec<u8>> {
    if let Some((_, b)) = proof_cache().lock().iter().find(|(p, _)| p == path) {
        return Some(b.clone());
    }
    std::fs::read(path).ok()
}

/// Builds this node's proposal for `round` on the block certified by `qc`.
#[allow(clippy::too_many_arguments)]
async fn propose(
    chain: &Arc<Chain>,
    pool: &Arc<TxPool>,
    round: u64,
    qc: &Qc<BlsScheme>,
    cert: Vec<u8>,
    slot_ms: u64,
    fee_recipient: Address,
    key: &BlsSecretKey,
) -> Result<(BlockInfo, Vec<u8>)> {
    // The parent may still be validating when its QC forms; give it a moment.
    let mut parent = None;
    for _ in 0..40 {
        if let Some(h) = chain.header_of(&qc.block)? {
            parent = Some(h);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let parent = parent.context("parent block not available")?;
    // Pace blocks: at least one slot after the parent.
    let earliest = parent.timestamp * 1000 + slot_ms;
    let now = now_ms();
    if earliest > now {
        tokio::time::sleep(Duration::from_millis(earliest - now)).await;
    }
    let timestamp = (now_ms() / 1000).max(parent.timestamp + 1);
    let height = parent.number + 1;
    let reveal = key.sign(&randao_msg(chain.config().chain_id, height));
    let extra: Bytes = [round.to_be_bytes().as_slice(), reveal.as_slice()].concat().into();
    let candidates = {
        let r = chain.store().reader()?;
        let base_fee = chain.next_base_fee()?;
        pool.best(base_fee, &HeadState(&r))
    };
    let (chain2, parent_hash) = (chain.clone(), qc.block);
    let built = tokio::task::spawn_blocking(move || {
        chain2.build_on(&parent_hash, candidates, timestamp, fee_recipient, extra, cert)
    })
    .await??;
    let payload = bolt_sync::announce_for(&built.bundle).encode();
    Ok((
        BlockInfo { hash: built.hash, parent: qc.block, round, height: built.header.number },
        payload,
    ))
}

/// Proposals this node could not validate because it did not have their parent yet (it missed
/// the parent's proposal, e.g. while restarting). Without them every later proposal fails the
/// same way: each one builds on the previous proposal, which this node never kept, while the
/// catch-up import of committed blocks stays a block or two behind. A proposal whose parent is
/// one of these validates that parent (and its cached ancestors) first.
#[derive(Clone, Default)]
struct Orphans(Arc<parking_lot::Mutex<VecDeque<Proposal<BlsScheme>>>>);

/// Cached orphan proposals and how many ancestors one proposal may pull in.
const ORPHANS: usize = 64;
const ORPHAN_DEPTH: usize = 16;

impl Orphans {
    fn keep(&self, p: &Proposal<BlsScheme>) {
        let mut q = self.0.lock();
        if q.iter().any(|x| x.block.hash == p.block.hash) {
            return;
        }
        if q.len() >= ORPHANS {
            q.pop_front();
        }
        q.push_back(p.clone());
    }

    /// Cached ancestors of `p`, oldest first.
    fn ancestors(&self, p: &Proposal<BlsScheme>) -> Vec<Proposal<BlsScheme>> {
        let q = self.0.lock();
        let mut out = Vec::new();
        let mut want = p.block.parent;
        while out.len() < ORPHAN_DEPTH {
            let Some(a) = q.iter().find(|x| x.block.hash == want) else { break };
            want = a.block.parent;
            out.push(a.clone());
        }
        out.reverse();
        out
    }
}

fn unknown_parent(e: &anyhow::Error) -> bool {
    e.chain().any(|c| matches!(c.downcast_ref::<ChainError>(), Some(ChainError::UnknownParent(_))))
}

/// [`validate`], first validating the proposal's cached orphan ancestors when its parent is
/// unknown; keeps it as an orphan if the parent is still missing.
async fn validate_with_ancestors(
    chain: &Arc<Chain>,
    net: &NetHandle,
    p: &Proposal<BlsScheme>,
    via: Option<PeerId>,
    committee_keys: &[bls::BlsPublicKey],
    orphans: &Orphans,
) -> Result<()> {
    let first = validate(chain, net, p, via, committee_keys).await;
    let Err(e) = first else { return Ok(()) };
    if !unknown_parent(&e) {
        return Err(e);
    }
    let ancestors = orphans.ancestors(p);
    // The oldest block we have a proposal for builds on one we never saw (proposed while this
    // node was away, and by now final elsewhere): fetch that stretch by its envelopes.
    let root = ancestors.first().unwrap_or(p);
    if let Err(e) = fetch_missing_parents(chain, net, root, via).await {
        tracing::debug!(height = root.block.height, "could not fetch missing parents: {e:#}");
    }
    let mut last = Err(e);
    if !ancestors.is_empty() {
        let mut ok = true;
        for a in &ancestors {
            if let Err(e) = validate(chain, net, a, None, committee_keys).await {
                tracing::debug!(height = a.block.height, "orphan ancestor still invalid: {e:#}");
                ok = false;
                break;
            }
        }
        if ok {
            tracing::info!(
                height = p.block.height,
                ancestors = ancestors.len(),
                "validated missed parent proposals"
            );
            last = validate(chain, net, p, via, committee_keys).await;
        }
    } else {
        last = validate(chain, net, p, via, committee_keys).await;
    }
    if let Err(e) = &last
        && unknown_parent(e)
    {
        orphans.keep(p);
    }
    last
}

/// Fetches, by walking envelope parents from `p`'s, the blocks between this node's known blocks
/// and `p`'s parent, and verifies them as pending blocks (oldest first). They are ones the
/// committee already finalized or voted for, served by the peers that have them; they are
/// executed and checked here like any block, and committed only through consensus.
async fn fetch_missing_parents(
    chain: &Arc<Chain>,
    net: &NetHandle,
    p: &Proposal<BlsScheme>,
    via: Option<PeerId>,
) -> Result<()> {
    let a = Announce::decode(&p.payload).context("payload is not an announcement")?;
    let env = Envelope::decode(&a.envelope)?;
    let mut peers: Vec<PeerId> = via.into_iter().collect();
    peers.extend(net.peers().await.into_iter().filter(|x| Some(*x) != via));
    let mut missing: Vec<Envelope> = Vec::new();
    let mut next = env.parent;
    while let Some(cid) = next {
        anyhow::ensure!(missing.len() < ORPHAN_DEPTH, "more than {ORPHAN_DEPTH} blocks behind");
        let bytes = net.fetch(&[cid], &peers).await?.remove(&cid).context("envelope not served")?;
        verify(&cid, &bytes)?;
        let e = Envelope::decode(&bytes)?;
        let hash = e.block_hash().context("envelope without a block hash")?;
        if chain.header_of(&hash)?.is_some() {
            break;
        }
        next = e.parent;
        missing.push(e);
    }
    for e in missing.into_iter().rev() {
        let mut want = vec![e.header];
        want.extend(e.chunks.iter().copied());
        let have = net.fetch(&want, &peers).await?;
        for (c, b) in &have {
            verify(c, b)?;
        }
        let (height, certs) = (e.height, bolt_chain::Certs::of(&e));
        let block = decode_block(e, |c| have.get(c).cloned())?;
        let chain = chain.clone();
        tokio::task::spawn_blocking(move || {
            chain.verify_block(&block.header, block.transactions, certs)
        })
        .await??;
        tracing::debug!(height, "fetched a missed parent block");
    }
    Ok(())
}

/// Checks a proposal: data present and verified against CIDs, certificate and RANDAO reveal
/// consistent with the consensus metadata, block executes on its parent.
async fn validate(
    chain: &Arc<Chain>,
    net: &NetHandle,
    p: &Proposal<BlsScheme>,
    via: Option<PeerId>,
    committee_keys: &[bls::BlsPublicKey],
) -> Result<()> {
    let a = Announce::decode(&p.payload).context("payload is not an announcement")?;
    verify(&a.root, &a.envelope)?;
    let env = Envelope::decode(&a.envelope)?;
    anyhow::ensure!(env.height == p.block.height, "envelope height");
    anyhow::ensure!(env.block_hash() == Some(p.block.hash), "envelope names a different block");
    if is_start_anchor(chain, &p.qc) {
        anyhow::ensure!(
            env.qc.is_empty(),
            "first block after genesis or the terminal block carries a certificate"
        );
    } else if p.qc.is_anchor() {
        // First block of an epoch: the envelope must prove the anchor final.
        let f = Finality::new(chain.clone());
        let proof =
            f.parent_proof(&env.qc).context("first block of the epoch lacks the epoch proof")?;
        anyhow::ensure!(
            f.check(p.qc.height, &p.qc.block, &proof) == Verdict::Final,
            "invalid epoch proof"
        );
    } else {
        anyhow::ensure!(
            env.qc == encode_cert(&Cert::Qc(p.qc.clone())),
            "envelope certificate differs from the proposal's"
        );
    }
    let mut have: HashMap<bolt_ipld::Cid, Vec<u8>> = HashMap::new();
    have.insert(env.header, a.header.clone());
    for b in a.inline {
        have.insert(b.cid, b.data);
    }
    let missing: Vec<_> = env.chunks.iter().filter(|c| !have.contains_key(c)).copied().collect();
    if !missing.is_empty() {
        let mut peers: Vec<PeerId> = via.into_iter().collect();
        peers.extend(net.peers().await.into_iter().filter(|x| Some(*x) != via));
        have.extend(net.fetch(&missing, &peers).await?);
    }
    let qc = bolt_chain::Certs::of(&env);
    let block = decode_block(env, |c| have.get(c).cloned())?;
    let h = &block.header;
    anyhow::ensure!(h.parent_hash == p.block.parent, "header parent differs");
    anyhow::ensure!(round_of(&h.extra_data) == Some(p.block.round), "header round differs");
    let reveal = BlsSignature::from_slice(&h.extra_data[8..]);
    let pk = committee_keys.get(p.proposer as usize).context("unknown proposer")?;
    anyhow::ensure!(
        bls::verify(pk, &randao_msg(chain.config().chain_id, h.number), &reveal),
        "bad RANDAO reveal"
    );
    anyhow::ensure!(h.timestamp * 1000 <= now_ms() + 3_000, "timestamp in the future");
    let chain = chain.clone();
    tokio::task::spawn_blocking(move || chain.verify_block(&block.header, block.transactions, qc))
        .await??;
    Ok(())
}

/// Validator CLI options.
#[derive(Debug, clap::Args)]
pub struct ValidatorArgs {
    /// Genesis file.
    #[arg(long, default_value = "genesis/dev.json")]
    pub genesis: PathBuf,
    /// Data directory.
    #[arg(long, default_value = "data/validator")]
    pub datadir: PathBuf,
    /// BLS key file (`boltchain keys new` / `keys dev`); repeat for several validators. Without
    /// any, the node follows the chain (and mines with `--mine`) but does not validate.
    #[arg(long)]
    pub key: Vec<PathBuf>,
    /// JSON-RPC listen address.
    #[arg(long, default_value = "127.0.0.1:8545")]
    pub rpc: std::net::SocketAddr,
    /// Minimum seconds between blocks (defaults to the genesis slot).
    #[arg(long)]
    pub block_time: Option<u64>,
    /// Base round timeout in milliseconds (defaults to two slots).
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    /// Mining while the chain is in its mining phase.
    #[command(flatten)]
    pub mining: crate::miner::MiningArgs,
    /// P2P options.
    #[command(flatten)]
    pub p2p: crate::p2p::P2pArgs,
    /// Storage options.
    #[command(flatten)]
    pub storage: StorageArgs,
    /// Serve Prometheus metrics (`/metrics`) and a JSON status (`/health`), e.g.
    /// `127.0.0.1:9017`.
    #[arg(long)]
    pub metrics: Option<std::net::SocketAddr>,
}

/// Storage-layer options (ADR 0009).
#[derive(Debug, Clone, Default, clap::Args)]
pub struct StorageArgs {
    /// Start a fresh datadir from the state snapshot of this block instead of genesis:
    /// `<number>:<hash>` of a recent epoch-end block you trust (from another node, an explorer
    /// or a friend). The snapshot is taken from the network and checked against it.
    #[arg(long)]
    pub checkpoint: Option<String>,
    /// Snapshot root CID for `--checkpoint` (otherwise the first matching announcement is used).
    #[arg(long)]
    pub snapshot: Option<String>,
    /// Keep every block body (no pruning). Default: bodies older than the recent window are
    /// dropped, except the epochs assigned to this node's validators.
    #[arg(long)]
    pub archive: bool,
    /// Do not take or announce state snapshots.
    #[arg(long)]
    pub no_snapshots: bool,
    /// Serve the blockstore over HTTP as a trustless IPFS gateway, e.g. `127.0.0.1:8080`.
    #[arg(long)]
    pub gateway: Option<std::net::SocketAddr>,
    /// Serve the block explorer (web interface and `/api`) on the gateway address (default
    /// `127.0.0.1:8080`) and keep the address index it needs (about 10–20% more disk).
    #[arg(long)]
    pub explorer: bool,
    /// Contract names for the explorer: JSON `{ "<address>": "<name>" }` or a deployment record
    /// with a `contracts` map (e.g. `scripts/uniswap-v4/deployments/8018.json`). Repeatable.
    #[arg(long = "explorer-labels", value_name = "FILE")]
    pub explorer_labels: Vec<std::path::PathBuf>,
    /// `Certificates` contract for the explorer's evidence certificates (ADR 0016): the explorer
    /// then accepts uploads for certificate storage deals and announces them to providers.
    #[arg(long, value_name = "ADDRESS")]
    pub certificates: Option<alloy_primitives::Address>,
    /// CAFECA wallet the certificate page pays with.
    #[arg(long, default_value = "https://cafeca.io")]
    pub cafeca_wallet: String,
    /// Serve history as a storage provider without stake (ADR 0012) for this account's registered
    /// provider ids: keep the epochs assigned to them. Repeatable. Register first with
    /// `boltchain wallet storage-register`. The node also keeps the SwarmStorage deals assigned
    /// to them (ADR 0014).
    #[arg(long = "storage-account", value_name = "ADDRESS")]
    pub storage_accounts: Vec<alloy_primitives::Address>,
    /// Enable `bolt_hostBlocks` / `bolt_getBlocks` on the JSON-RPC (SwarmStorage deals, ADR 0014):
    /// `boltchain storage put/get` go through them. Anyone reaching the RPC can then store blocks
    /// on this node, so bind the RPC to localhost when enabling it.
    #[arg(long)]
    pub rpc_storage: bool,
    /// Command line (run by `sh -c`) that judges the compute disputes (ADR 0011) given to this
    /// node's validators on a verifier panel, e.g. `boltchain judge --backend http://127.0.0.1:8080
    /// --model 1=qwen2.5-7b`: it receives the job in `BOLT_*` environment variables and prints
    /// `fault` or `ok` (anything else abstains). Needs `--rpc-storage` to read the files. Without
    /// it the validators do not vote on disputes.
    #[arg(long, value_name = "COMMAND")]
    pub verifier_cmd: Option<String>,
    /// Relay signed actions of accounts without BOLT (`bolt_relay`: compute providers' signed
    /// registrations, acceptances and receipts, enclave checkpoints), paying the gas from this
    /// account key file and earning the fees those actions pay.
    #[arg(long, value_name = "FILE")]
    pub relay_wallet: Option<PathBuf>,
    /// Smallest fee, in BOLT, the relay accepts per action.
    #[arg(long, default_value = "0.001")]
    pub relay_min_fee: String,
    /// Directory of TPM vendor root certificates (DER or PEM) this node's validators trust when
    /// their verifier panel appraises T2 machines (ADR 0013). Without it they abstain on T2
    /// requests (development chains also trust the simulated vendor).
    #[arg(long, value_name = "DIR")]
    pub tpm_roots: Option<PathBuf>,
}

/// Runs a validator node until Ctrl-C.
pub async fn run(args: ValidatorArgs) -> Result<()> {
    let genesis = crate::devnet::load_genesis(&args.genesis)?;
    let mut keys = Vec::new();
    for p in &args.key {
        let (k, encrypted) = keys::load_key_file(p)?;
        if !encrypted {
            // Mainnet (the only non-dev chain) refuses unencrypted validator keys.
            if !genesis.dev {
                bail!(
                    "{} is not encrypted; convert it with `boltchain keys encrypt` before running on mainnet",
                    p.display()
                );
            }
            tracing::warn!(key = %p.display(), "validator key is not encrypted (`boltchain keys encrypt`)");
        }
        keys.push(k);
    }
    let chain = Arc::new(Chain::open(&args.datadir, &genesis)?);
    let cfg = chain.config().clone();
    let pool = Arc::new(TxPool::new(bolt_txpool::PoolConfig::new(
        cfg.chain_id,
        cfg.gas_limit,
        cfg.min_base_fee_wei,
    )));
    if let Some(g) = args.mining.gas_target {
        chain.set_gas_target(g);
    }
    let (net, events) = args.p2p.start(&args.datadir, chain.clone(), None).await?;
    let (events, mut storage_rx) = crate::storage::split(events);
    if let Some(cp) = &args.storage.checkpoint {
        let (number, hash) = crate::storage::parse_checkpoint(cp)?;
        let root = args.storage.snapshot.as_deref().map(bolt_ipld::Cid::try_from).transpose()?;
        crate::storage::checkpoint_sync(&chain, &net, number, hash, root, &mut storage_rx).await?;
    }
    let storage = crate::storage::Storage::new(
        chain.clone(),
        net.clone(),
        crate::storage::StorageConfig {
            snapshots: !args.storage.no_snapshots,
            prune: !args.storage.archive,
            keys: keys.clone(),
            storage_accounts: args.storage.storage_accounts.clone(),
            hosted_file: Some(args.datadir.join("hosted-deals.txt")),
            verifier: args.storage.verifier_cmd.clone().map(|cmd| {
                Arc::new(crate::storage::CommandJudge { cmd, rpc: format!("http://{}", args.rpc) })
                    as Arc<dyn crate::storage::Judge>
            }),
            tpm_roots: crate::attest::tpm_roots(args.storage.tpm_roots.as_deref(), genesis.dev)?,
            ..Default::default()
        },
    );
    let host: Option<Arc<dyn bolt_rpc::BlockHost>> = args.storage.rpc_storage.then(|| {
        Arc::new(crate::storage::RpcHost {
            storage: storage.clone(),
            rt: tokio::runtime::Handle::current(),
        }) as Arc<dyn bolt_rpc::BlockHost>
    });
    let storage_task = tokio::spawn(storage.clone().run(storage_rx));
    if args.storage.explorer {
        crate::explorer::spawn_address_index(chain.clone())?;
        if !args.storage.explorer_labels.is_empty() {
            let n = crate::explorer::load_labels(&args.storage.explorer_labels)?;
            tracing::info!(contracts = n, "explorer labels loaded");
        }
        let addr = args.storage.gateway.unwrap_or(([127, 0, 0, 1], 8080).into());
        let certs = args.storage.certificates.map(|a| {
            let st = storage.clone();
            let announce: Arc<dyn Fn(bolt_ipld::Cid) + Send + Sync> = Arc::new(move |root| {
                if let Err(e) = st.host(root, &[]) {
                    tracing::warn!("announcing certificate deal {root}: {e:#}");
                }
            });
            Arc::new(crate::certificates::Certs::new(
                a,
                args.storage.cafeca_wallet.clone(),
                Some(announce),
                Some(args.datadir.join("cert-uploads.json")),
            ))
        });
        let ex = crate::explorer::Explorer {
            chain: chain.clone(),
            pool: Some(pool.clone()),
            certs: certs.clone(),
        };
        crate::explorer::start(addr, ex).await?;
    } else if let Some(addr) = args.storage.gateway {
        crate::gateway::start(addr, chain.clone()).await?;
    }
    if let Some(addr) = args.metrics {
        crate::metrics::start(addr, chain.clone(), Some(pool.clone())).await?;
    }
    crate::metrics::spawn_status(chain.clone(), net.clone(), Some(pool.clone()));
    let relay = match &args.storage.relay_wallet {
        Some(f) => {
            let s = crate::wallet::load_wallet(f)?;
            let min = crate::wallet::parse_bolt(&args.storage.relay_min_fee)?;
            let ip = if args.rpc.ip().is_unspecified() {
                std::net::IpAddr::from([127, 0, 0, 1])
            } else {
                args.rpc.ip()
            };
            let r = crate::relay::Relay::new(format!("http://{ip}:{}", args.rpc.port()), s, min);
            tracing::info!(account = %r.address(), "relaying signed actions (bolt_relay)");
            Some(Arc::new(r) as Arc<dyn bolt_rpc::CallRelay>)
        }
        None => None,
    };
    let ctx = bolt_rpc::RpcContext {
        chain: chain.clone(),
        pool: pool.clone(),
        client_version: crate::CLIENT_VERSION.to_string(),
        forwarder: None,
        host,
        relay,
    };
    let (addr, handle) = bolt_rpc::start(args.rpc, ctx).await?;
    tracing::info!(%addr, keys = keys.len(), "JSON-RPC listening");
    let slot_ms = args.block_time.unwrap_or(cfg.slot_seconds) * 1000;
    let miner = args.mining.config()?;
    let v = Validator {
        chain,
        pool,
        net,
        keys,
        cfg: ValidatorConfig {
            slot_ms,
            base_timeout_ms: args.timeout_ms.unwrap_or(slot_ms * 2),
            state_dir: args.datadir.join("consensus"),
        },
        miner,
    };
    let task = tokio::spawn(v.run(events));
    tokio::signal::ctrl_c().await?;
    task.abort();
    storage_task.abort();
    handle.stop()?;
    Ok(())
}

/// Aborts a task when dropped.
struct AbortOnDrop(Option<tokio::task::JoinHandle<Result<()>>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(t) = self.0.take() {
            t.abort();
        }
    }
}
