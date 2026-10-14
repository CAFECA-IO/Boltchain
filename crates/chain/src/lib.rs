//! Chain state machine: genesis initialisation, block production and block import.
//!
//! Execution reads a consistent snapshot of the store while RPC readers keep running; the only
//! write transaction is the final commit of each block (state, tries, block, history pruning).
//!
//! Blocks come in two kinds (ADR 0007): *mined* blocks until the epoch PoS starts in
//! (`ConsensusRegistry.posEpoch`), sealed with RandomBOLT at the ASERT difficulty and chosen by
//! total difficulty ([`pow`]); and blocks of the PoS committee afterwards, final once certified.

use alloy_consensus::{Header, Transaction as _, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
pub mod history;
mod overlay;
pub mod pow;

use bolt_exec::{
    BlockExecutor, BlockInput, BlockParams, ExecutedBlock, TxRejection, next_base_fee,
};
use bolt_ipld::{BlockBundle, Cid};
use bolt_pow::{AsertParams, Pow};
use bolt_primitives::params::GAS_LIMIT_RANGE;
use bolt_primitives::{Genesis, genesis::ChainConfig};
use bolt_store::{InitAccount, StateView, Store, StoreError, StoredBlock};
use bolt_system::{CertVotes, EpochRules, Phase};
use parking_lot::Mutex;
use revm::database::{OriginalValuesKnown, states::StateChangeset};
use std::{collections::BTreeMap, path::Path};
use std::{collections::HashMap, sync::Arc};

/// Chain error.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Storage failure.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The datadir belongs to a different chain.
    #[error("datadir genesis {stored} does not match genesis file {expected}")]
    GenesisMismatch {
        /// Genesis hash in the datadir.
        stored: B256,
        /// Genesis hash of the file.
        expected: B256,
    },
    /// Fatal execution error.
    #[error("execution: {0}")]
    Exec(String),
    /// A block failed validation.
    #[error("invalid block: {0}")]
    InvalidBlock(String),
    /// The parent is neither the committed head nor a known pending block.
    #[error("unknown parent {0}")]
    UnknownParent(B256),
    /// A heavier chain forks off deeper than [`bolt_primitives::params::MAX_REORG_DEPTH`] blocks,
    /// or below a block the PoS committee made final. It is not followed automatically.
    #[error("refusing reorganisation: {0}")]
    DeepReorg(String),
}

/// Result alias.
pub type Result<T, E = ChainError> = std::result::Result<T, E>;

/// Outcome of producing a block.
#[derive(Debug, Clone)]
pub struct BuiltBlock {
    /// The sealed header.
    pub header: Header,
    /// Its hash.
    pub hash: B256,
    /// Hashes of included transactions.
    pub included: Vec<B256>,
    /// Transactions that were tried and rejected: hash, reason, and whether the rejection is
    /// permanent (invalid) rather than "did not fit in this block".
    pub rejected: Vec<(B256, String, bool)>,
    /// The block's IPFS representation (already stored in the blockstore).
    pub bundle: BlockBundle,
}

/// The chain.
#[derive(Debug)]
pub struct Chain {
    store: Store,
    config: ChainConfig,
    rules: EpochRules,
    genesis_hash: B256,
    pending: Mutex<HashMap<B256, Arc<PendingBlock>>>,
    /// PoW verification.
    pow: Pow,
    asert: AsertParams,
    /// Mined blocks off the canonical chain (candidates for a reorganisation).
    side: Mutex<HashMap<B256, pow::SideBlock>>,
    /// Serializes mined-block imports and reorganisations.
    import_lock: Mutex<()>,
    /// Gas limit this node's blocks move towards (0: keep the parent's).
    gas_target: std::sync::atomic::AtomicU64,
    /// Storage-audit certificates to include in this node's next blocks.
    audit_queue: Mutex<Vec<Vec<u8>>>,
}

/// A pending block, the included transaction hashes and the skipped ones (hash, reason, drop).
type Executed = (Arc<PendingBlock>, Vec<B256>, Vec<(B256, String, bool)>);

impl Chain {
    /// Opens the datadir, writing genesis on first start.
    pub fn open(datadir: impl AsRef<Path>, genesis: &Genesis) -> Result<Self> {
        let store = Store::open(datadir)?;
        let genesis_header =
            bolt_system::genesis_header(genesis).map_err(|e| ChainError::Exec(e.to_string()))?;
        let expected = genesis_header.hash_slow();
        let head = store.reader()?.head()?;
        match head {
            None => {
                let alloc: BTreeMap<Address, InitAccount> = bolt_system::genesis_alloc(genesis)
                    .map_err(|e| ChainError::Exec(e.to_string()))?
                    .into_iter()
                    .map(|(a, acc)| {
                        let storage = acc
                            .storage
                            .into_iter()
                            .filter(|(_, v)| !v.is_zero())
                            .map(|(k, v)| (k, U256::from_be_bytes(v.0)))
                            .collect();
                        (
                            a,
                            InitAccount {
                                nonce: acc.nonce,
                                balance: acc.balance,
                                code: acc.code,
                                storage,
                            },
                        )
                    })
                    .collect();
                let w = store.writer()?;
                let root = w.init_state(&alloc)?;
                let header = genesis_header;
                if root != header.state_root {
                    return Err(ChainError::Exec(format!(
                        "genesis state root mismatch: store {root}, genesis {}",
                        header.state_root
                    )));
                }
                let bundle = bolt_ipld::bundle(&header, &[], None, vec![]);
                w.put_ipld_bundle(0, &bundle.root, &bundle.blocks)?;
                w.put_block(&StoredBlock { header, transactions: vec![], senders: vec![] }, &[])?;
                w.commit()?;
                tracing::info!(hash = %expected, "initialised genesis");
            }
            Some(_) => {
                let stored = store.reader()?.block_hash(0)?.unwrap_or_default();
                if stored != expected {
                    return Err(ChainError::GenesisMismatch { stored, expected });
                }
            }
        }
        let pc = &genesis.config.pow;
        let algorithm = match pc.algorithm {
            bolt_primitives::genesis::PowAlgorithm::RandomBolt => bolt_pow::Algorithm::RandomBolt,
            bolt_primitives::genesis::PowAlgorithm::Keccak => bolt_pow::Algorithm::Keccak,
        };
        Ok(Self {
            store,
            config: genesis.config.clone(),
            rules: EpochRules::from_config(&genesis.config, genesis.timestamp),
            genesis_hash: expected,
            pending: Mutex::new(HashMap::new()),
            pow: Pow::light(algorithm),
            asert: AsertParams {
                spacing: pc.block_seconds,
                half_life: pc.half_life_seconds,
                initial: pc.initial_difficulty,
                minimum: U256::from(1),
            },
            side: Mutex::new(HashMap::new()),
            import_lock: Mutex::new(()),
            gas_target: std::sync::atomic::AtomicU64::new(0),
            audit_queue: Mutex::new(Vec::new()),
        })
    }

    /// Proof-of-work function (for miners that verify with the same settings).
    pub fn pow(&self) -> &Pow {
        &self.pow
    }

    /// Sets the gas limit this node's blocks move towards (0: keep the parent's). Each block may
    /// move it by less than 1/1024 of the parent's, within [`GAS_LIMIT_RANGE`].
    pub fn set_gas_target(&self, gas: u64) {
        self.gas_target.store(gas, std::sync::atomic::Ordering::Relaxed);
    }

    /// Consensus phase in the committed head state.
    pub fn phase(&self) -> Result<Phase> {
        let r = self.store.reader()?;
        bolt_system::queries::phase(&StateView::latest(&r), self.config.chain_id)
            .map_err(|e| ChainError::Exec(e.to_string()))
    }

    /// Fork id at the committed head (EIP-2124 layout, ADR 0008 §2).
    pub fn fork_id(&self) -> Result<bolt_primitives::forks::ForkId> {
        let head = self.head()?.number;
        Ok(bolt_primitives::forks::fork_id(
            &self.genesis_hash,
            bolt_primitives::forks::forks(self.config.chain_id),
            head,
        ))
    }

    /// Total difficulty of the committed head.
    pub fn head_total_difficulty(&self) -> Result<U256> {
        let r = self.store.reader()?;
        let n = r.head()?.unwrap_or(0);
        Ok(r.total_difficulty(n)?.unwrap_or_default())
    }

    /// The underlying store (for RPC reads).
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Chain parameters.
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Genesis block hash.
    pub fn genesis_hash(&self) -> B256 {
        self.genesis_hash
    }

    /// Current head header.
    pub fn head(&self) -> Result<Header> {
        let r = self.store.reader()?;
        let n = r.head()?.unwrap_or(0);
        r.header(n)?.ok_or_else(|| ChainError::Exec("missing head header".into()))
    }

    /// Epoch rules.
    pub fn rules(&self) -> &EpochRules {
        &self.rules
    }

    /// Base fee the next block will use.
    pub fn next_base_fee(&self) -> Result<u64> {
        Ok(next_base_fee(&self.head()?, self.config.min_base_fee_wei))
    }

    /// Gas limit of this node's next block on `parent`.
    fn next_gas_limit(&self, parent: &Header) -> u64 {
        let target = self.gas_target.load(std::sync::atomic::Ordering::Relaxed);
        next_gas_limit(parent.gas_limit, target)
    }

    #[allow(clippy::too_many_arguments)]
    fn params_for(
        &self,
        parent: &Header,
        kind: &BlockKind,
        timestamp: u64,
        beneficiary: Address,
        extra_data: Bytes,
        gas_limit: u64,
        nonce: alloy_primitives::B64,
    ) -> BlockParams {
        let prevrandao = match kind {
            BlockKind::Mined { .. } => {
                keccak256([parent.mix_hash.as_slice(), parent.hash_slow().as_slice()].concat())
            }
            BlockKind::Pos => mix_hash(parent, &extra_data),
        };
        let difficulty = match kind {
            BlockKind::Mined { difficulty, .. } => *difficulty,
            BlockKind::Pos => U256::ZERO,
        };
        BlockParams {
            input: BlockInput {
                chain_id: self.config.chain_id,
                number: parent.number + 1,
                timestamp,
                beneficiary,
                gas_limit,
                base_fee: next_base_fee(parent, self.config.min_base_fee_wei),
                prevrandao,
            },
            parent_hash: parent.hash_slow(),
            parent_beacon_root: B256::ZERO,
            extra_data,
            difficulty,
            nonce,
        }
    }

    /// Kind of the block after `parent` (whose post-state is `db`): mined, with its difficulty,
    /// or produced by the PoS committee.
    fn kind_of<D: revm::DatabaseRef>(&self, db: D, parent: &Header) -> Result<BlockKind>
    where
        D::Error: std::fmt::Debug,
    {
        let phase = bolt_system::queries::phase(db, self.config.chain_id)
            .map_err(|e| ChainError::Exec(e.to_string()))?;
        if phase.is_pos(&self.rules, parent.number + 1) {
            return Ok(BlockKind::Pos);
        }
        Ok(BlockKind::Mined {
            difficulty: self.difficulty_after(parent)?,
            checkpointing: phase.is_checkpointing(&self.rules, parent.number + 1),
        })
    }

    /// Queues a storage-audit certificate for this node's next blocks (kept until recorded).
    pub fn add_audit_cert(&self, cert: Vec<u8>) {
        let mut q = self.audit_queue.lock();
        if !q.contains(&cert) {
            q.push(cert);
        }
        if q.len() > 64 {
            q.remove(0);
        }
    }

    /// The index of the epoch that ends just before block `number` (the first block of the next
    /// epoch), built from the envelopes of this block's own chain. Its IPFS blocks are stored so
    /// the node serves them.
    fn epoch_index_before(&self, number: u64, ancestors: &[Arc<PendingBlock>]) -> Result<Vec<u8>> {
        let epoch = self.rules.epoch_of(number - 1);
        let first = epoch * self.rules.epoch_slots + 1;
        let r = self.store.reader()?;
        let mut envelopes = Vec::with_capacity((number - first) as usize);
        for h in first..number {
            let cid = match ancestors.iter().find(|a| a.header.number == h) {
                Some(a) => a.bundle.root,
                None => r.envelope_root(h)?.ok_or_else(|| {
                    ChainError::Exec(format!("missing envelope of block {h} for the epoch index"))
                })?,
            };
            envelopes.push(cid);
        }
        drop(r);
        let (root, blocks) = bolt_ipld::history::epoch_index(epoch, first, &envelopes);
        let w = self.store.writer()?;
        for (c, b) in &blocks {
            w.put_ipld(c, b)?;
        }
        w.commit()?;
        Ok(root.to_bytes())
    }

    /// Checks the panel certificates of block `number` against the parent state `db`:
    /// storage audits (current epoch, pending task) and, once the `swarm` fork is in force on
    /// the public testnet (from genesis elsewhere), compute verdicts (a job still disputed and
    /// assigned to that epoch's verifier panel); each needs more than 2/3 of its panel. A received
    /// block (`strict`) must carry only valid ones; a producer drops the rest. Returns the audit
    /// results, the verdicts and the certificates kept.
    #[allow(clippy::type_complexity)]
    fn check_audits<D: revm::DatabaseRef + Copy>(
        &self,
        db: D,
        number: u64,
        certs: Vec<Vec<u8>>,
        strict: bool,
    ) -> Result<(
        Vec<bolt_system::AuditResult>,
        Vec<(u64, bool)>,
        Vec<(u64, bool, B256)>,
        Vec<Vec<u8>>,
    )>
    where
        D::Error: std::fmt::Debug,
    {
        use bolt_system::{abi::*, addresses::*, queries};
        let mut results: Vec<bolt_system::AuditResult> = Vec::new();
        let mut verdicts: Vec<(u64, bool)> = Vec::new();
        let mut attests: Vec<(u64, bool, B256)> = Vec::new();
        let mut kept = Vec::new();
        if certs.is_empty() {
            return Ok((results, verdicts, attests, kept));
        }
        let chain_id = self.config.chain_id;
        let q = |e| ChainError::Exec(format!("{e}"));
        // Compute verdicts first: they never decode as audit certificates.
        let verdicts_on =
            bolt_primitives::forks::active(chain_id, bolt_primitives::forks::SWARM, number);
        let mut panels: HashMap<u64, Vec<bolt_primitives::bls::BlsPublicKey>> = HashMap::new();
        let mut rest = Vec::new();
        let tee_on = bolt_primitives::forks::active(chain_id, bolt_primitives::forks::TEE, number);
        let mut attest_panels: HashMap<u64, Vec<bolt_primitives::bls::BlsPublicKey>> =
            HashMap::new();
        for bytes in certs {
            // TEE attestation results (ADR 0013): a request still waiting, assigned to the
            // certificate's epoch.
            if let Some(c) = bolt_consensus::AttestCert::decode(&bytes) {
                let mut ok = tee_on && !attests.iter().any(|(r, _, _)| *r == c.request);
                if ok {
                    let n = queries::call(db, chain_id, LEASES, IEnclaveLease::requestCountCall {})
                        .map_err(q)?;
                    ok = c.request != 0 && U256::from(c.request) <= n;
                }
                if ok {
                    let r = queries::call(
                        db,
                        chain_id,
                        LEASES,
                        IEnclaveLease::requestCall { r: U256::from(c.request) },
                    )
                    .map_err(q)?;
                    ok = r.state == 1 && r.epoch == c.epoch && r.epoch != 0;
                }
                if ok && !attest_panels.contains_key(&c.epoch) {
                    let ids = queries::call(
                        db,
                        chain_id,
                        LEASES,
                        IEnclaveLease::panelCall { epoch: c.epoch },
                    )
                    .map_err(q)?;
                    let keys = if ids.is_empty() {
                        Vec::new()
                    } else {
                        queries::call(db, chain_id, STAKING, IStakingManager::keysOfCall { ids })
                            .map_err(q)?
                            .pubkeys
                            .chunks_exact(48)
                            .map(bolt_primitives::bls::BlsPublicKey::from_slice)
                            .collect()
                    };
                    attest_panels.insert(c.epoch, keys);
                }
                if ok && c.verify(chain_id, &attest_panels[&c.epoch]) {
                    attests.push((c.request, c.ok, B256::from(c.machine_id())));
                    kept.push(bytes);
                } else if strict {
                    return Err(ChainError::InvalidBlock("invalid attestation certificate".into()));
                }
                continue;
            }
            let Some(c) = bolt_consensus::VerdictCert::decode(&bytes) else {
                rest.push(bytes);
                continue;
            };
            let mut ok = verdicts_on && !verdicts.iter().any(|(j, _)| *j == c.job);
            if ok {
                let id = U256::from(c.job);
                let d = queries::call(db, chain_id, COMPUTE, IComputeMarket::disputesCall { id })
                    .map_err(q)?;
                let j = queries::call(db, chain_id, COMPUTE, IComputeMarket::jobCall { id });
                // JobState::Disputed = 4.
                ok = d.panelEpoch == c.epoch && d.panelEpoch != 0 && j.is_ok_and(|j| j.state == 4);
            }
            if ok && !panels.contains_key(&c.epoch) {
                let ids = queries::call(
                    db,
                    chain_id,
                    COMPUTE,
                    IComputeMarket::panelCall { epoch: c.epoch },
                )
                .map_err(q)?;
                let keys = if ids.is_empty() {
                    Vec::new()
                } else {
                    queries::call(db, chain_id, STAKING, IStakingManager::keysOfCall { ids })
                        .map_err(q)?
                        .pubkeys
                        .chunks_exact(48)
                        .map(bolt_primitives::bls::BlsPublicKey::from_slice)
                        .collect()
                };
                panels.insert(c.epoch, keys);
            }
            if ok && c.verify(chain_id, &panels[&c.epoch]) {
                verdicts.push((c.job, c.fault));
                kept.push(bytes);
            } else if strict {
                return Err(ChainError::InvalidBlock("invalid verdict certificate".into()));
            }
        }
        let certs = rest;
        if certs.is_empty() {
            return Ok((results, verdicts, attests, kept));
        }
        let epoch = self.rules.epoch_of(number);
        let audits =
            queries::call(db, chain_id, SWARM, ISwarmStorage::auditsCall { epoch }).map_err(q)?;
        let panel = if audits.panel.is_empty() {
            Vec::new()
        } else {
            let keys = queries::call(
                db,
                chain_id,
                STAKING,
                IStakingManager::keysOfCall { ids: audits.panel.clone() },
            )
            .map_err(q)?;
            keys.pubkeys
                .chunks_exact(48)
                .map(bolt_primitives::bls::BlsPublicKey::from_slice)
                .collect()
        };
        for bytes in certs {
            let ok = bolt_consensus::AuditCert::decode(&bytes).filter(|c| {
                c.epoch == epoch
                    && (c.task as usize) < audits.states.len()
                    && audits.states[c.task as usize] == 0
                    && !results.iter().any(|r| r.task == c.task)
                    && c.verify(chain_id, &panel)
            });
            match ok {
                Some(c) => {
                    results.push(bolt_system::AuditResult {
                        epoch: c.epoch,
                        task: c.task,
                        passed: c.passed,
                    });
                    kept.push(bytes);
                }
                None if strict => {
                    return Err(ChainError::InvalidBlock("invalid audit certificate".into()));
                }
                None => {}
            }
        }
        Ok((results, verdicts, attests, kept))
    }

    /// A certificate carried by a mined block in phase B: a QC of the current epoch's checkpoint
    /// committee (it earns its signers their share of the block rewards), checked against the
    /// committee in the parent state `db`.
    fn check_checkpoint_cert<D: revm::DatabaseRef + Copy>(
        &self,
        db: D,
        cert: &[u8],
        number: u64,
        checkpointing: bool,
    ) -> Result<()>
    where
        D::Error: std::fmt::Debug,
    {
        let invalid = ChainError::InvalidBlock;
        if !checkpointing {
            return Err(invalid("mined blocks outside phase B carry no certificate".into()));
        }
        let Some(bolt_consensus::Cert::Qc(qc)) =
            bolt_consensus::decode_cert::<bolt_consensus::BlsScheme>(cert)
        else {
            return Err(invalid("a mined block may only carry a checkpoint QC".into()));
        };
        if qc.is_anchor() || qc.epoch != self.rules.epoch_of(number) {
            return Err(invalid(format!("checkpoint QC of epoch {} in block {number}", qc.epoch)));
        }
        let c = bolt_system::queries::committee_at(db, self.config.chain_id, qc.epoch)
            .map_err(|e| ChainError::Exec(e.to_string()))?
            .ok_or_else(|| invalid(format!("no committee for epoch {}", qc.epoch)))?;
        let scheme = bolt_consensus::BlsScheme::new(c.pubkeys.clone(), &[]);
        let set = bolt_consensus::ValidatorSet::from_seats(
            c.committee.members.len(),
            c.committee.seats.iter().map(|s| *s as bolt_consensus::ValidatorIndex).collect(),
        );
        if !qc.verify(&scheme, &set, self.config.chain_id, qc.epoch, &B256::ZERO) {
            return Err(invalid("invalid checkpoint QC".into()));
        }
        Ok(())
    }

    /// ASERT difficulty of a mined child of `parent`.
    pub fn difficulty_after(&self, parent: &Header) -> Result<U256> {
        let solve_time = if parent.number <= 1 {
            0
        } else {
            let gp = self
                .header_any(&parent.parent_hash)?
                .ok_or(ChainError::UnknownParent(parent.parent_hash))?;
            parent.timestamp.saturating_sub(gp.timestamp)
        };
        Ok(bolt_pow::next_difficulty(&self.asert, parent.number, parent.difficulty, solve_time))
    }

    /// Header of `hash`, whether committed or pending.
    pub fn header_of(&self, hash: &B256) -> Result<Option<Header>> {
        if let Some(p) = self.pending.lock().get(hash) {
            return Ok(Some(p.header.clone()));
        }
        let r = self.store.reader()?;
        match r.block_number(hash)? {
            Some(n) => Ok(r.header(n)?),
            None => Ok(None),
        }
    }

    /// Header of `hash`: committed, pending or a mined side-chain block.
    pub fn header_any(&self, hash: &B256) -> Result<Option<Header>> {
        if let Some(h) = self.header_of(hash)? {
            return Ok(Some(h));
        }
        Ok(self.side.lock().get(hash).map(|b| b.header.clone()))
    }

    /// Forgets a pending block (e.g. a mining template that went stale).
    pub fn drop_pending(&self, hash: &B256) {
        self.pending.lock().remove(hash);
    }

    /// A pending (executed, not yet final) block.
    pub fn pending(&self, hash: &B256) -> Option<Arc<PendingBlock>> {
        self.pending.lock().get(hash).cloned()
    }

    /// Pending blocks from the committed head up to `parent` (oldest first). Empty when `parent`
    /// is the head itself.
    fn pending_chain(&self, head: &Header, parent: &B256) -> Result<Vec<Arc<PendingBlock>>> {
        let head_hash = head.hash_slow();
        let pending = self.pending.lock();
        let mut chain = Vec::new();
        let mut cur = *parent;
        while cur != head_hash {
            let p = pending.get(&cur).ok_or_else(|| ChainError::UnknownParent(cur))?.clone();
            if p.header.number <= head.number {
                return Err(ChainError::UnknownParent(cur));
            }
            cur = p.header.parent_hash;
            chain.push(p);
        }
        chain.reverse();
        Ok(chain)
    }

    /// Executes a block on `parent` (the committed head or a pending block) without committing.
    /// With `expected`, the transactions must all execute and the header must match exactly;
    /// otherwise candidates that do not fit are skipped.
    fn execute_on(
        &self,
        parent_hash: &B256,
        mut params_fn: impl FnMut(&Header, &BlockKind) -> BlockParams,
        txs: Vec<(TxEnvelope, Address)>,
        expected: Option<&Header>,
        certs: Certs,
    ) -> Result<Executed> {
        let Certs { qc, audits } = certs;
        let head = self.head()?;
        let ancestors = self.pending_chain(&head, parent_hash)?;
        let parent_header = match ancestors.last() {
            Some(p) => p.header.clone(),
            None => head.clone(),
        };
        let mut changes = overlay::Changes::default();
        for a in &ancestors {
            changes.push(a.header.number, a.hash, &a.changes);
        }
        let (cert_epoch, cert_round, bitmap) = bolt_consensus::cert_votes(&qc);
        let votes = CertVotes { epoch: cert_epoch, round: cert_round, bitmap };

        let mut included = Vec::new();
        let mut rejected = Vec::new();
        let (executed, audits) = {
            let reader = self.store.reader()?;
            let view = StateView::latest(&reader);
            let db = overlay::Overlay { base: &view, changes: &changes };
            let kind = self.kind_of(&db, &parent_header)?;
            let params = params_fn(&parent_header, &kind);
            let producer = match kind {
                BlockKind::Pos => bolt_system::Producer::Committee,
                BlockKind::Mined { checkpointing: true, .. } => {
                    bolt_system::Producer::MinerWithCheckpoints
                }
                BlockKind::Mined { .. } => bolt_system::Producer::Miner,
            };
            if let Some(exp) = expected {
                self.check_kind(exp, &kind, &parent_header, &ancestors, &head)?;
            }
            if let BlockKind::Mined { checkpointing, .. } = kind
                && !qc.is_empty()
            {
                self.check_checkpoint_cert(&db, &qc, parent_header.number + 1, checkpointing)?;
            }
            let number = params.input.number;
            // History (ADR 0009): the previous epoch's index, and the audit certificates carried
            // (all must verify in a received block; a producer keeps only the valid ones).
            let epoch_index = if self.rules.is_epoch_start(number) && number > 1 {
                Some(self.epoch_index_before(number, &ancestors)?)
            } else {
                None
            };
            let (audit_results, verdicts, attestations, audits) =
                self.check_audits(&db, number, audits, expected.is_some())?;
            let history = bolt_system::HistoryInputs {
                epoch_index,
                audits: audit_results,
                verdicts,
                attestations,
            };
            let mut ex =
                BlockExecutor::new(&db, params).map_err(|e| ChainError::Exec(e.to_string()))?;
            // Hard forks activating at this block (ADR 0008 §2).
            for fork in bolt_primitives::forks::forks(self.config.chain_id) {
                if fork.activation != number {
                    continue;
                }
                for c in fork.changes {
                    let storage: Vec<(U256, U256)> = c
                        .storage
                        .iter()
                        .map(|(k, v)| (U256::from_be_bytes(k.0), U256::from_be_bytes(v.0)))
                        .collect();
                    ex.apply_irregular(c.address, c.code.map(Bytes::from_static), &storage)
                        .map_err(|e| ChainError::Exec(format!("fork {}: {e}", fork.name)))?;
                }
            }
            bolt_system::pre_block(
                &mut ex,
                &self.rules,
                &parent_header,
                &votes,
                producer,
                &history,
            )
            .map_err(|e| ChainError::Exec(format!("system calls: {e}")))?;
            for (tx, sender) in txs {
                if expected.is_none() && ex.gas_remaining() < 21_000 {
                    break;
                }
                let hash = *tx.tx_hash();
                match ex.add(tx, sender).map_err(|e| ChainError::Exec(e.to_string()))? {
                    Ok(_) => included.push(hash),
                    Err(e) if expected.is_some() => {
                        return Err(ChainError::InvalidBlock(format!("tx {hash}: {e}")));
                    }
                    Err(e) => {
                        let permanent = matches!(e, TxRejection::Invalid(_) | TxRejection::Blob);
                        rejected.push((hash, e.to_string(), permanent));
                    }
                }
            }
            (ex.finish(), audits)
        };
        let number = executed.params.input.number;

        // State root: apply ancestors and this block in a write transaction that is then dropped
        // (aborted). Nothing reaches the database until the block is committed.
        let root = {
            let w = self.store.writer()?;
            for a in &ancestors {
                w.apply_bundle(a.header.number, a.executed.bundle.clone())?;
            }
            w.apply_bundle(number, executed.bundle.clone())?
        };
        let header = executed.header(root);
        if let Some(exp) = expected
            && exp != &header
        {
            return Err(ChainError::InvalidBlock(format!(
                "header mismatch (state root {} vs {}, gas limit {} vs {}, base fee {:?} vs {:?}, mix {} vs {})",
                header.state_root,
                exp.state_root,
                header.gas_limit,
                exp.gas_limit,
                header.base_fee_per_gas,
                exp.base_fee_per_gas,
                header.mix_hash,
                exp.mix_hash
            )));
        }
        let parent_root = match ancestors.last() {
            Some(p) => Some(p.bundle.root),
            None => self.store.reader()?.envelope_root(head.number)?,
        };
        let bundle =
            bolt_ipld::bundle_with_audits(&header, &executed.transactions, parent_root, qc, audits);
        let hash = header.hash_slow();
        // Publish the IPFS blocks right away so peers can fetch them before the block is final
        // (validators must hold the data to vote), and record the block so that a restart can
        // execute it again ([`Chain::restore_pending`]): a certificate may name it while no node
        // still has it in memory.
        {
            let w = self.store.writer()?;
            for (cid, data) in &bundle.blocks {
                w.put_ipld(cid, data)?;
            }
            w.put_pending(header.number, &hash, &bundle.root)?;
            w.commit()?;
        }
        let (changes_plain, _) =
            executed.bundle.to_plain_state_and_reverts(OriginalValuesKnown::Yes);
        let pending =
            Arc::new(PendingBlock { hash, header, executed, changes: changes_plain, bundle });
        self.pending.lock().insert(hash, pending.clone());
        Ok((pending, included, rejected))
    }

    /// Kind-specific rules for an expected (received) header, checked before executing it: the
    /// seal and difficulty of a mined block, the absence of both under PoS.
    fn check_kind(
        &self,
        exp: &Header,
        kind: &BlockKind,
        parent: &Header,
        ancestors: &[Arc<PendingBlock>],
        head: &Header,
    ) -> Result<()> {
        let invalid = ChainError::InvalidBlock;
        match kind {
            BlockKind::Pos => {
                if !exp.difficulty.is_zero() || exp.nonce != alloy_primitives::B64::ZERO {
                    return Err(invalid(format!(
                        "block {} is after the switch to PoS but carries a PoW seal",
                        exp.number
                    )));
                }
            }
            BlockKind::Mined { difficulty, .. } => {
                if exp.difficulty != *difficulty {
                    return Err(invalid(format!(
                        "difficulty {} != {difficulty} (ASERT)",
                        exp.difficulty
                    )));
                }
                if exp.extra_data.len() > 32 {
                    return Err(invalid("extra data over 32 bytes".into()));
                }
                let h = bolt_pow::seed_height(exp.number);
                let seed = if h == parent.number {
                    parent.hash_slow()
                } else if h <= head.number {
                    self.store
                        .reader()?
                        .block_hash(h)?
                        .ok_or(ChainError::UnknownParent(B256::ZERO))?
                } else {
                    ancestors
                        .iter()
                        .find(|a| a.header.number == h)
                        .map(|a| a.hash)
                        .ok_or(ChainError::UnknownParent(B256::ZERO))?
                };
                self.check_seal(exp, &seed)?;
            }
        }
        Ok(())
    }

    /// Whether `header` is sealed under the RandomBOLT key of seed block `seed`.
    fn check_seal(&self, header: &Header, seed: &B256) -> Result<()> {
        let key = bolt_pow::key_for(seed);
        match self.pow.verify(&key, header) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ChainError::InvalidBlock(format!(
                "block {} does not meet its difficulty",
                header.number
            ))),
            Err(e) => Err(ChainError::Exec(e.to_string())),
        }
    }

    /// Builds a block on `parent` from candidate transactions, without committing it.
    #[allow(clippy::too_many_arguments)]
    pub fn build_on(
        &self,
        parent: &B256,
        candidates: impl IntoIterator<Item = (TxEnvelope, Address)>,
        timestamp: u64,
        beneficiary: Address,
        extra_data: Bytes,
        certs: impl Into<Certs>,
    ) -> Result<BuiltBlock> {
        let mut certs = certs.into();
        // Producers include the audit certificates this node collected (invalid ones are dropped
        // during execution).
        if certs.audits.is_empty() {
            certs.audits = self.audit_queue.lock().clone();
        }
        let beacon = if certs.qc.is_empty() { B256::ZERO } else { keccak256(&certs.qc) };
        let (pending, included, rejected) = self.execute_on(
            parent,
            |ph, kind| {
                let mut p = self.params_for(
                    ph,
                    kind,
                    timestamp.max(ph.timestamp + 1),
                    beneficiary,
                    extra_data.clone(),
                    self.next_gas_limit(ph),
                    alloy_primitives::B64::ZERO,
                );
                p.parent_beacon_root = beacon;
                p
            },
            candidates.into_iter().collect(),
            None,
            certs,
        )?;
        Ok(BuiltBlock {
            header: pending.header.clone(),
            hash: pending.hash,
            included,
            rejected,
            bundle: pending.bundle.clone(),
        })
    }

    /// Verifies a block proposed by someone else on top of a committed or pending parent, without
    /// committing it. `qc` must be the envelope's certificate for the parent.
    pub fn verify_block(
        &self,
        header: &Header,
        transactions: Vec<TxEnvelope>,
        certs: impl Into<Certs>,
    ) -> Result<Arc<PendingBlock>> {
        let certs = certs.into();
        if let Some(p) = self.pending(&header.hash_slow()) {
            return Ok(p);
        }
        let parent = self
            .header_of(&header.parent_hash)?
            .ok_or(ChainError::UnknownParent(header.parent_hash))?;
        let invalid = ChainError::InvalidBlock;
        if header.number != parent.number + 1 {
            return Err(invalid("wrong number".into()));
        }
        if header.timestamp <= parent.timestamp {
            return Err(invalid("timestamp not after parent".into()));
        }
        if !valid_gas_limit(parent.gas_limit, header.gas_limit) {
            return Err(invalid(format!(
                "gas limit {} not within 1/1024 of {} or outside {GAS_LIMIT_RANGE:?}",
                header.gas_limit, parent.gas_limit
            )));
        }
        // Base fee, difficulty and the RANDAO mix are recomputed during execution and compared
        // with the header; the kind-specific rules (seal, certificate) are checked first.
        let expected_beacon = if certs.qc.is_empty() { B256::ZERO } else { keccak256(&certs.qc) };
        if header.parent_beacon_block_root != Some(expected_beacon) {
            return Err(invalid("parent certificate hash mismatch".into()));
        }
        let senders: Vec<Address> = {
            use rayon::prelude::*;
            transactions
                .par_iter()
                .map(|tx| tx.recover_signer())
                .collect::<Result<_, _>>()
                .map_err(|_| invalid("bad signature".into()))?
        };
        let (h, number) = (header.clone(), header.number);
        let (pending, _, _) = self.execute_on(
            &header.parent_hash,
            |ph, kind| {
                let mut p = self.params_for(
                    ph,
                    kind,
                    h.timestamp,
                    h.beneficiary,
                    h.extra_data.clone(),
                    h.gas_limit,
                    h.nonce,
                );
                p.parent_beacon_root = expected_beacon;
                p
            },
            transactions.into_iter().zip(senders).collect(),
            Some(header),
            certs,
        )?;
        debug_assert_eq!(pending.header.number, number);
        Ok(pending)
    }

    /// Executes again, from the blockstore, the recorded pending blocks among `wanted` and their
    /// pending ancestors (after a restart: the consensus engine's certified and voted blocks are
    /// in no node's memory any more, and without them no leader can build on the highest
    /// certificate). Blocks that no longer apply are forgotten. Returns how many were restored.
    pub fn restore_pending(&self, wanted: &[B256]) -> Result<usize> {
        let head = self.head()?;
        let head_hash = head.hash_slow();
        let records = self.store.reader()?.pending_blocks(head.number)?;
        let mut blocks = HashMap::new();
        {
            let r = self.store.reader()?;
            for (number, hash, root) in records {
                let decoded =
                    r.ipld(&root)?.and_then(|b| bolt_ipld::Envelope::decode(&b).ok()).and_then(
                        |env| bolt_ipld::decode_block(env, |c| r.ipld(c).ok().flatten()).ok(),
                    );
                match decoded {
                    Some(d) if d.header.number == number && d.header.hash_slow() == hash => {
                        blocks.insert(hash, d);
                    }
                    _ => tracing::warn!(number, %hash, "pending block not in the blockstore"),
                }
            }
        }
        // `wanted` and their ancestors down to the head, lowest first.
        let mut chosen: Vec<B256> = Vec::new();
        for w in wanted {
            let mut path = Vec::new();
            let mut cur = *w;
            while let Some(b) = blocks.get(&cur) {
                if chosen.contains(&cur) || path.contains(&cur) {
                    break;
                }
                path.push(cur);
                cur = b.header.parent_hash;
            }
            chosen.extend(path);
        }
        chosen.sort_by_key(|h| blocks[h].header.number);
        let mut restored = 0;
        for hash in chosen {
            if self.pending(&hash).is_some() {
                continue;
            }
            let b = &blocks[&hash];
            if b.header.parent_hash != head_hash && self.pending(&b.header.parent_hash).is_none() {
                continue; // its parent did not restore, or it is on a branch below the head
            }
            match self.verify_block(&b.header, b.transactions.clone(), Certs::of(&b.envelope)) {
                Ok(_) => restored += 1,
                Err(e) => {
                    tracing::warn!(number = b.header.number, %hash, "pending block not restored: {e}")
                }
            }
        }
        Ok(restored)
    }

    /// Makes a pending block final. It must extend the committed head.
    pub fn commit_pending(&self, hash: &B256) -> Result<Header> {
        let p = self.pending(hash).ok_or(ChainError::UnknownParent(*hash))?;
        let head = self.head()?;
        if p.header.parent_hash != head.hash_slow() {
            return Err(ChainError::InvalidBlock(format!(
                "block {} does not extend head {}",
                p.header.number, head.number
            )));
        }
        let number = p.header.number;
        let w = self.store.writer()?;
        let root = w.apply_bundle(number, p.executed.bundle.clone())?;
        if root != p.header.state_root {
            return Err(ChainError::Exec(format!(
                "state root changed between execution and commit at {number}"
            )));
        }
        w.put_ipld_bundle(number, &p.bundle.root, &p.bundle.blocks)?;
        w.put_block(
            &StoredBlock {
                header: p.header.clone(),
                transactions: p.executed.transactions.clone(),
                senders: p.executed.senders.clone(),
            },
            &p.executed.receipts,
        )?;
        w.prune_history(number)?;
        w.prune_pending(number)?;
        w.commit()?;
        // Drop pending blocks that can no longer be built upon, and side blocks too old to win.
        self.pending.lock().retain(|_, b| b.header.number > number);
        let horizon = number.saturating_sub(bolt_primitives::params::MAX_REORG_DEPTH);
        self.side.lock().retain(|_, b| b.header.number > horizon);
        tracing::debug!(number, hash = %p.hash, root = %p.bundle.root, gas = p.header.gas_used, "committed block");
        Ok(p.header.clone())
    }

    /// Produces and immediately commits the next block (single-producer devnet).
    pub fn build_block(
        &self,
        candidates: impl IntoIterator<Item = (TxEnvelope, Address)>,
        timestamp: u64,
        beneficiary: Address,
    ) -> Result<BuiltBlock> {
        let head = self.head()?.hash_slow();
        let built =
            self.build_on(&head, candidates, timestamp, beneficiary, Bytes::new(), vec![])?;
        self.commit_pending(&built.hash)?;
        Ok(built)
    }

    /// Validates and imports a final block produced elsewhere. Every transaction must execute.
    pub fn import_block(&self, header: &Header, transactions: Vec<TxEnvelope>) -> Result<B256> {
        self.import_block_with_root(header, transactions, None)
    }

    /// Like [`Chain::import_block`], additionally requiring the block's IPFS envelope to hash to
    /// `root` (the CID it was announced under). The envelope's QC is taken from `qc`.
    pub fn import_block_with_root(
        &self,
        header: &Header,
        transactions: Vec<TxEnvelope>,
        root: Option<Cid>,
    ) -> Result<B256> {
        self.import_final(header, transactions, root, vec![])
    }

    /// Imports a final block whose envelope carries `qc`.
    pub fn import_final(
        &self,
        header: &Header,
        transactions: Vec<TxEnvelope>,
        root: Option<Cid>,
        certs: impl Into<Certs>,
    ) -> Result<B256> {
        let head = self.head()?;
        if header.parent_hash != head.hash_slow() {
            return Err(ChainError::InvalidBlock(format!("does not extend head {}", head.number)));
        }
        let pending = self.verify_block(header, transactions, certs)?;
        if let Some(exp) = root
            && exp != pending.bundle.root
        {
            self.pending.lock().remove(&pending.hash);
            return Err(ChainError::InvalidBlock(format!(
                "envelope {} != announced {exp}",
                pending.bundle.root
            )));
        }
        self.commit_pending(&pending.hash)?;
        Ok(pending.hash)
    }
}

/// The certificates a block's envelope carries: the parent's QC (or epoch proof, or a checkpoint
/// QC in a mined block) and storage-audit certificates (ADR 0009).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Certs {
    /// Envelope `qc` field.
    pub qc: Vec<u8>,
    /// Envelope `audits` field.
    pub audits: Vec<Vec<u8>>,
}

impl Certs {
    /// The certificates of an envelope.
    pub fn of(env: &bolt_ipld::Envelope) -> Self {
        Self { qc: env.qc.clone(), audits: env.audits.iter().map(|a| a.to_vec()).collect() }
    }
}

impl From<Vec<u8>> for Certs {
    fn from(qc: Vec<u8>) -> Self {
        Self { qc, audits: Vec::new() }
    }
}

/// How a block is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// Mined (before PoS starts), at this difficulty.
    Mined {
        /// ASERT difficulty.
        difficulty: U256,
        /// Phase B: a committee finalizes checkpoints (the miner gets 60% of the reward).
        checkpointing: bool,
    },
    /// Produced and certified by the PoS committee.
    Pos,
}

/// Whether a block may use `gas_limit` after a parent with `parent_gas_limit`: within the hard
/// range and less than 1/1024 of the parent's away from it (as Ethereum).
pub fn valid_gas_limit(parent_gas_limit: u64, gas_limit: u64) -> bool {
    let max_delta = parent_gas_limit / 1024;
    (GAS_LIMIT_RANGE.0..=GAS_LIMIT_RANGE.1).contains(&gas_limit)
        && gas_limit.abs_diff(parent_gas_limit) < max_delta.max(1)
}

/// Gas limit of a block after a parent with `parent_gas_limit`, moving towards `target` (0: keep).
pub fn next_gas_limit(parent_gas_limit: u64, target: u64) -> u64 {
    let step = (parent_gas_limit / 1024).saturating_sub(1);
    let target = if target == 0 { parent_gas_limit } else { target };
    let target = target.clamp(GAS_LIMIT_RANGE.0, GAS_LIMIT_RANGE.1);
    let next = if target > parent_gas_limit {
        parent_gas_limit + step.min(target - parent_gas_limit)
    } else {
        parent_gas_limit - step.min(parent_gas_limit - target)
    };
    next.clamp(GAS_LIMIT_RANGE.0, GAS_LIMIT_RANGE.1)
}

/// Length of `extra_data` in validator-produced blocks: round (8 bytes) + RANDAO reveal (96 bytes).
pub const EXTRA_DATA_LEN: usize = 8 + 96;

/// RANDAO mix of a PoS block after `parent` (ADR 0006 §6): with a reveal in `extra_data`,
/// `keccak(parent.mix_hash ‖ keccak(reveal))`; otherwise (single-producer devnet)
/// `keccak(parent.mix_hash ‖ number)`. Validators check the reveal's signature before voting.
/// Mined blocks use `keccak(parent.mix_hash ‖ parent hash)`.
pub fn mix_hash(parent: &Header, extra_data: &[u8]) -> B256 {
    if extra_data.len() == EXTRA_DATA_LEN {
        keccak256([parent.mix_hash.as_slice(), keccak256(&extra_data[8..]).as_slice()].concat())
    } else {
        keccak256([parent.mix_hash.as_slice(), &(parent.number + 1).to_be_bytes()].concat())
    }
}

/// A block that was executed and verified but is not final yet.
#[derive(Debug)]
pub struct PendingBlock {
    /// Block hash.
    pub hash: B256,
    /// Header.
    pub header: Header,
    /// Execution output (transactions, receipts, state changes with reverts).
    pub executed: ExecutedBlock,
    /// Plain state changes, used to execute children before this block is final.
    pub changes: StateChangeset,
    /// IPFS representation (already in the blockstore).
    pub bundle: BlockBundle,
}

/// Serialized size of a transaction (for pool accounting).
pub fn tx_size(tx: &TxEnvelope) -> usize {
    tx.encode_2718_len()
}

/// Maximum cost a transaction may charge its sender.
pub fn max_cost(tx: &TxEnvelope) -> U256 {
    U256::from(tx.gas_limit()) * U256::from(tx.max_fee_per_gas()) + tx.value()
}

#[cfg(test)]
mod compute_tests;
#[cfg(test)]
mod epoch_tests;
#[cfg(test)]
mod history_tests;
#[cfg(test)]
mod pow_tests;
#[cfg(test)]
mod tests;
