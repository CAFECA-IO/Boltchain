//! Pre-block system calls (ADR 0006 §8), run after EIP-4788 / EIP-2935 and before transactions.

use crate::{abi::*, addresses::*, committee::Committee};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolCall;
use bolt_exec::{BlockExecutor, block::BlockError};
use bolt_primitives::params::{
    CHECKPOINT_MINER_BPS, DEAL_AUDIT_TASKS, WEI_PER_BOLT, consensus_reward, emission_era, share,
    storage_reward,
};
use revm::DatabaseRef;

/// Epoch and phase rules for the hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRules {
    /// Blocks per epoch.
    pub epoch_slots: u64,
    /// Committee seats.
    pub committee_size: u32,
    /// Stake-finality threshold: minimum number of stakers.
    pub checkpoint_min_stakers: u64,
    /// Stake-finality threshold: minimum total stake, in wei.
    pub checkpoint_min_stake: U256,
    /// Blocks that must bury a mined block before it is proposed as a checkpoint.
    pub checkpoint_depth: u64,
    /// Epochs of history every validator keeps; older ones are sharded and audited.
    pub history_recent_epochs: u64,
    /// PoS threshold: minimum number of stakers.
    pub pos_min_stakers: u64,
    /// PoS threshold: minimum total stake, in wei.
    pub pos_min_stake: U256,
    /// Consecutive epochs the thresholds must hold; minimum stake age for the first committee.
    pub pos_streak: u64,
    /// Genesis timestamp: emission eras count chain time from it (ADR 0012).
    pub genesis_timestamp: u64,
}

impl EpochRules {
    /// Rules of a chain configuration (dev chains may lower the PoS thresholds).
    pub fn from_config(c: &bolt_primitives::genesis::ChainConfig, genesis_timestamp: u64) -> Self {
        let (stakers, stake, streak) = c.pos_thresholds();
        let (cp_stakers, cp_stake) = c.checkpoint_thresholds();
        Self {
            epoch_slots: c.epoch_slots,
            committee_size: c.committee_size,
            checkpoint_min_stakers: cp_stakers as u64,
            checkpoint_min_stake: U256::from(cp_stake) * U256::from(WEI_PER_BOLT),
            checkpoint_depth: c.checkpoint_depth(),
            history_recent_epochs: c.history_recent_epochs(),
            pos_min_stakers: stakers as u64,
            pos_min_stake: U256::from(stake) * U256::from(WEI_PER_BOLT),
            pos_streak: streak,
            genesis_timestamp,
        }
    }

    /// Epoch of block `height` (genesis and heights 1..=L are epoch 0).
    pub fn epoch_of(&self, height: u64) -> u64 {
        if height == 0 { 0 } else { (height - 1) / self.epoch_slots }
    }

    /// Whether `height` is the first block of its epoch.
    pub fn is_epoch_start(&self, height: u64) -> bool {
        height >= 1 && (height - 1).is_multiple_of(self.epoch_slots)
    }

    /// Last block of epoch `epoch`.
    pub fn epoch_end(&self, epoch: u64) -> u64 {
        (epoch + 1) * self.epoch_slots
    }
}

/// Consensus phase recorded in `ConsensusRegistry` (ADR 0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Phase {
    /// First epoch whose committee finalizes mined blocks (phase B), once scheduled.
    pub checkpoint_epoch: Option<u64>,
    /// First PoS epoch, once scheduled.
    pub pos_epoch: Option<u64>,
    /// Consecutive epochs the stake-finality thresholds have held.
    pub checkpoint_streak: u64,
    /// Consecutive epochs the PoS thresholds have held.
    pub streak: u64,
}

impl Phase {
    /// Whether mined block `height` belongs to an epoch whose committee finalizes checkpoints.
    pub fn is_checkpointing(&self, rules: &EpochRules, height: u64) -> bool {
        self.checkpoint_epoch.is_some_and(|e| rules.epoch_of(height) >= e)
            && !self.is_pos(rules, height)
    }

    /// Whether epoch `epoch` is a phase-B epoch (committee finalizes mined blocks).
    pub fn is_checkpoint_epoch(&self, epoch: u64) -> bool {
        self.checkpoint_epoch.is_some_and(|e| epoch >= e)
            && self.pos_epoch.is_none_or(|p| epoch < p)
    }

    /// Whether the first PoS epoch's anchor (the terminal block) was finalized by phase B, so the
    /// first PoS block carries its proof rather than nothing.
    pub fn terminal_is_checkpointed(&self) -> bool {
        match (self.checkpoint_epoch, self.pos_epoch) {
            (Some(c), Some(p)) => c < p,
            _ => false,
        }
    }

    /// Whether block `height` is produced by the PoS committee (otherwise it is mined).
    pub fn is_pos(&self, rules: &EpochRules, height: u64) -> bool {
        self.pos_epoch.is_some_and(|e| rules.epoch_of(height) >= e)
    }

    /// The last mined block (the PoS anchor), once PoS is scheduled after a mining phase.
    pub fn terminal_height(&self, rules: &EpochRules) -> Option<u64> {
        match self.pos_epoch {
            Some(0) | None => None,
            Some(e) => Some(rules.epoch_end(e - 1)),
        }
    }
}

/// The votes certified by a block's certificate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertVotes {
    /// Epoch whose committee signed.
    pub epoch: u64,
    /// Round of the certificate (each round's votes are counted once).
    pub round: u64,
    /// Signer bitmap over that committee's members.
    pub bitmap: Vec<u8>,
}

fn view<D: DatabaseRef, C: SolCall>(
    exec: &mut BlockExecutor<D>,
    to: Address,
    call: C,
) -> Result<C::Return, BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let out = exec.view_call(to, call.abi_encode().into())?;
    C::abi_decode_returns(&out).map_err(|e| BlockError::Evm(format!("decode {to}: {e}")))
}

fn sys<D: DatabaseRef, C: SolCall>(
    exec: &mut BlockExecutor<D>,
    to: Address,
    call: C,
) -> Result<C::Return, BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let out = exec.system_call_data(to, call.abi_encode().into())?;
    C::abi_decode_returns(&out).map_err(|e| BlockError::Evm(format!("decode {to}: {e}")))
}

/// A storage audit decided by a panel certificate the chain verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditResult {
    /// Epoch of the task.
    pub epoch: u64,
    /// Task index.
    pub task: u16,
    /// Whether the provider served the data.
    pub passed: bool,
}

/// History data the node computes for a block's system calls (ADR 0009).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryInputs {
    /// First block of an epoch: the previous epoch's index CID (binary).
    pub epoch_index: Option<Vec<u8>>,
    /// Verified audit certificates carried by the block.
    pub audits: Vec<AuditResult>,
    /// Verified compute verdicts carried by the block (ADR 0011): (job id, provider at fault).
    pub verdicts: Vec<(u64, bool)>,
    /// Verified TEE attestation results (ADR 0013): (request id, accepted, machine ID).
    pub attestations: Vec<(u64, bool, B256)>,
}

/// How the block being executed is produced (for rewards).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Producer {
    /// Mined, phase A: the miner gets the whole block reward.
    Miner,
    /// Mined, phase B: the miner gets 60%; the committee earns the rest by participation.
    MinerWithCheckpoints,
    /// PoS committee.
    Committee,
}

/// Runs the Boltchain pre-block system calls for the block being built on `parent`.
pub fn pre_block<D: DatabaseRef>(
    exec: &mut BlockExecutor<D>,
    rules: &EpochRules,
    parent: &Header,
    votes: &CertVotes,
    producer: Producer,
    history: &HistoryInputs,
) -> Result<(), BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let number = exec.params().input.number;
    // 1. Burn accounting, block reward, participation.
    let burned = U256::from(parent.base_fee_per_gas.unwrap_or(0)) * U256::from(parent.gas_used);
    let mut minted = U256::ZERO;
    // ADR 0012: each block issues a consensus reward (31, 15, 7, 3, then 1 BOLT, halving every 4
    // years of chain time) and a 1 BOLT storage reward. Miners get the consensus reward at once
    // (60% of it in phase B); committees and storage are settled per epoch.
    let era = emission_era(rules.genesis_timestamp, exec.params().input.timestamp);
    if producer != Producer::Committee {
        minted = consensus_reward(era);
        if producer == Producer::MinerWithCheckpoints {
            minted = share(minted, CHECKPOINT_MINER_BPS);
        }
        if !minted.is_zero() {
            let beneficiary = exec.params().input.beneficiary;
            exec.credit(beneficiary, minted.to::<u128>())?;
        }
    }
    sys(
        exec,
        REWARDS,
        IRewardDistributor::onBlockCall {
            burned,
            minted,
            certEpoch: votes.epoch,
            certRound: votes.round,
            bitmap: Bytes::copy_from_slice(&votes.bitmap),
        },
    )?;
    if bolt_primitives::forks::active(exec.params().input.chain_id, bolt_primitives::forks::TEE, number) {
        assign_attestations(exec, parent, rules.epoch_of(number))?;
    }
    if !rules.is_epoch_start(number) {
        return record_audits(exec, history);
    }
    let epoch = rules.epoch_of(number);

    // 2. Rewards for the previous epoch's committee: none in phase A, the voters' 40% in phase B
    // (miners were paid per block), the whole consensus share under PoS.
    let before = crate::queries::phase_in(exec)?;
    if epoch >= 1 {
        // The previous epoch's blocks, at the reward of its last block (the parent): an epoch
        // straddling a halving is paid at the new rate, which a day's rounding never matters for.
        let blocks = U256::from(rules.epoch_slots);
        let parent_era = emission_era(rules.genesis_timestamp, parent.timestamp);
        let mut emission = consensus_reward(parent_era) * blocks;
        if before.is_checkpoint_epoch(epoch - 1) {
            emission = share(emission, 10_000 - CHECKPOINT_MINER_BPS);
        }
        let payout =
            view(exec, REWARDS, IRewardDistributor::previewCall { epoch: epoch - 1, emission })?;
        if !payout.is_zero() {
            exec.credit(REWARDS, payout.to::<u128>())?;
        }
        let paid =
            sys(exec, REWARDS, IRewardDistributor::settleCall { epoch: epoch - 1, emission })?;
        if paid != payout {
            return Err(BlockError::Evm(format!("settle paid {paid}, preview said {payout}")));
        }
        // Storage reward: 1 BOLT per block of the previous epoch, in equal parts per audit pass
        // (ADR 0009, 0012); nothing is issued when no audit passed.
        let storage = storage_reward() * blocks;
        let payout = view(
            exec,
            REWARDS,
            IRewardDistributor::previewStorageCall { epoch: epoch - 1, emission: storage },
        )?;
        if !payout.is_zero() {
            exec.credit(REWARDS, payout.to::<u128>())?;
        }
        let paid = sys(
            exec,
            REWARDS,
            IRewardDistributor::settleStorageCall { epoch: epoch - 1, emission: storage },
        )?;
        if paid != payout {
            return Err(BlockError::Evm(format!("storage paid {paid}, preview said {payout}")));
        }
        // The previous epoch's index: the node built it from the envelopes of that epoch.
        let cid = history
            .epoch_index
            .clone()
            .ok_or_else(|| BlockError::Evm(format!("missing index of epoch {}", epoch - 1)))?;
        sys(
            exec,
            SWARM,
            ISwarmStorage::recordEpochCall { epoch: epoch - 1, cid: Bytes::from(cid) },
        )?;
    }

    // 3. Phase: count the epochs the thresholds have held (T1: checkpoints, T2: PoS).
    let stats = view(exec, STAKING, IStakingManager::stakerStatsCall {})?;
    let t1 = stats.stakers >= U256::from(rules.checkpoint_min_stakers)
        && stats.total >= rules.checkpoint_min_stake;
    let t2 =
        stats.stakers >= U256::from(rules.pos_min_stakers) && stats.total >= rules.pos_min_stake;
    let phase = sys(
        exec,
        CONSENSUS,
        IConsensusRegistry::beginEpochCall {
            epoch,
            checkpointMet: t1,
            posMet: t2,
            streakRequired: rules.pos_streak,
        },
    )?;

    // Committee of the next epoch, from the first checkpoint epoch on. The first committee of
    // each phase (B and C) is drawn only from stake at least `pos_streak` epochs old (ADR 0007
    // §5), so nobody can buy a seat right before a phase starts.
    // 4. Storage audits of this epoch, once a committee exists to form the panel.
    if phase.cpScheduled && epoch >= phase.firstCheckpointEpoch {
        begin_audits(exec, rules, parent, epoch)?;
    }
    record_audits(exec, history)?;
    // Compute disputes (ADR 0011) waiting for a panel.
    assign_disputes(exec, parent, epoch)?;

    // 5. Committee of the next epoch.
    let next = epoch + 1;
    if !phase.cpScheduled || next < phase.firstCheckpointEpoch {
        return Ok(());
    }
    let first_of_phase =
        next == phase.firstCheckpointEpoch || (phase.scheduled && next == phase.firstPosEpoch);
    let min_age = if first_of_phase { rules.pos_streak } else { 0 };
    let mut committee = sample(exec, rules, parent, next, min_age)?;
    if committee.is_empty() && min_age > 0 {
        committee = sample(exec, rules, parent, next, 0)?;
    }
    if committee.is_empty() {
        // Nobody eligible (everyone exited or was slashed): keep the current committee.
        let c = view(exec, CONSENSUS, IConsensusRegistry::committeeCall { epoch })?;
        committee = Committee::from_parts(c.ids, c.weights, &c.seats);
    }
    sys(
        exec,
        CONSENSUS,
        IConsensusRegistry::setCommitteeCall {
            epoch: next,
            memberIds: committee.members.clone(),
            weights: committee.weights.clone(),
            seats: committee.seats_bytes(),
        },
    )?;
    Ok(())
}

/// Draws the audit panel (from the epoch's committee) and tasks: old epochs (their assignees, a
/// block each) and, once SwarmStorage is in force, deals (a copy and a block each).
fn begin_audits<D: DatabaseRef>(
    exec: &mut BlockExecutor<D>,
    rules: &EpochRules,
    parent: &Header,
    epoch: u64,
) -> Result<(), BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    use crate::history::{assignees, draw_panel, draw_targets, draw_task};
    let seed = seed(parent);
    let (mut providers, mut targets, mut heights) = (Vec::new(), Vec::new(), Vec::new());
    let indexed = view(exec, SWARM, ISwarmStorage::indexedEpochsCall {})?;
    let last_old = epoch.checked_sub(rules.history_recent_epochs + 1).filter(|l| indexed > *l);
    if let Some(last_old) = last_old {
        let snap = view(exec, STAKING, IStakingManager::snapshotCall { minAge: 0 })?;
        let mut validators = snap.ids;
        validators.sort_unstable();
        let storage = view(exec, SWARM, ISwarmStorage::activeStorageProvidersCall {})?;
        for (i, target) in draw_targets(&seed, epoch, last_old).into_iter().enumerate() {
            let cid = view(exec, SWARM, ISwarmStorage::epochIndexCall { epoch: target })?;
            let who = assignees(&cid, &validators, &storage);
            let first = target * rules.epoch_slots + 1;
            if let Some(t) =
                draw_task(&seed, epoch, i as u32, target, &who, first, rules.epoch_slots)
            {
                providers.push(t.provider);
                targets.push(t.target);
                heights.push(t.height);
            }
        }
    }
    let number = exec.params().input.number;
    let deals = if bolt_primitives::forks::active(
        exec.params().input.chain_id,
        bolt_primitives::forks::SWARM,
        number,
    ) {
        draw_deal_tasks(exec, &seed, epoch)?
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    if providers.is_empty() && deals.0.is_empty() {
        return Ok(());
    }
    let c = view(exec, CONSENSUS, IConsensusRegistry::committeeCall { epoch })?;
    if c.ids.is_empty() {
        return Ok(());
    }
    let panel = draw_panel(&seed, epoch, &c.ids);
    sys(exec, SWARM, ISwarmStorage::beginAuditsCall { epoch, panel, providers, targets, heights })?;
    if !deals.0.is_empty() {
        let (providers, deal_ids, indexes_) = deals;
        sys(
            exec,
            SWARM,
            ISwarmStorage::addDealAuditsCall { epoch, providers, dealIds: deal_ids, indexes_ },
        )?;
    }
    Ok(())
}

/// Deal audit tasks (ADR 0014): [`DEAL_AUDIT_TASKS`] draws, each a random deal still running, one
/// of its copies past its first epoch, and one of its blocks (up to 4 attempts per task).
#[allow(clippy::type_complexity)]
fn draw_deal_tasks<D: DatabaseRef>(
    exec: &mut BlockExecutor<D>,
    seed: &B256,
    epoch: u64,
) -> Result<(Vec<u32>, Vec<u64>, Vec<u64>), BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    use crate::history::draw_index;
    let (mut providers, mut deal_ids, mut indexes_) = (Vec::new(), Vec::new(), Vec::new());
    let count = view(exec, SWARM, ISwarmStorage::dealCountCall {})?;
    if count.is_zero() {
        return Ok((providers, deal_ids, indexes_));
    }
    let count = u64::try_from(count).unwrap_or(u64::MAX);
    for i in 0..DEAL_AUDIT_TASKS {
        for attempt in 0..4u32 {
            let n = i * 4 + attempt;
            let id = draw_index(seed, b"audit/deal", epoch, n, count);
            let d = view(exec, SWARM, ISwarmStorage::dealCall { id: U256::from(id) })?;
            if d.closed || epoch >= d.endEpoch || d.blocks == 0 {
                continue;
            }
            let s = view(exec, SWARM, ISwarmStorage::dealSlotsCall { id: U256::from(id) })?;
            let live: Vec<u32> = (0..s.providers.len())
                .filter(|k| s.open[*k] && s.since[*k] < epoch)
                .map(|k| s.providers[k])
                .collect();
            if live.is_empty() {
                continue;
            }
            let who =
                live[draw_index(seed, b"audit/deal-copy", epoch, n, live.len() as u64) as usize];
            providers.push(who);
            deal_ids.push(id);
            indexes_.push(draw_index(seed, b"audit/deal-block", epoch, n, d.blocks));
            break;
        }
    }
    Ok((providers, deal_ids, indexes_))
}

/// Assigns waiting compute disputes to a verifier panel: drawn from the epoch's committee, or in
/// the mining phase (no committee) from all stakers. Without either, disputes wait (and settle for
/// the provider after `VERDICT_TIMEOUT`).
fn assign_disputes<D: DatabaseRef>(
    exec: &mut BlockExecutor<D>,
    parent: &Header,
    epoch: u64,
) -> Result<(), BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    if view(exec, COMPUTE, IComputeMarket::pendingDisputesCall {})?.is_empty() {
        return Ok(());
    }
    let mut pool = view(exec, CONSENSUS, IConsensusRegistry::committeeCall { epoch })?.ids;
    if pool.is_empty() {
        pool = view(exec, STAKING, IStakingManager::snapshotCall { minAge: 0 })?.ids;
    }
    if pool.is_empty() {
        return Ok(());
    }
    // Independent of the audit panel drawn from the same seed.
    let seed = alloy_primitives::keccak256([seed(parent).as_slice(), b"compute/disputes"].concat());
    let members = crate::history::draw_panel(&seed, epoch, &pool);
    sys(exec, COMPUTE, IComputeMarket::assignDisputesCall { epoch, members })?;
    Ok(())
}

/// Assigns waiting TEE attestation requests (ADR 0013 §6.4) to the epoch's verifier panel,
/// drawn like the dispute panel (from the committee, or all stakers while mining) by the first
/// block of the epoch that has a request; later requests of the epoch go to the same panel.
fn assign_attestations<D: DatabaseRef>(
    exec: &mut BlockExecutor<D>,
    parent: &Header,
    epoch: u64,
) -> Result<(), BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    if view(exec, LEASES, IEnclaveLease::pendingAttestationsCall {})?.is_empty() {
        return Ok(());
    }
    if !view(exec, LEASES, IEnclaveLease::panelCall { epoch })?.is_empty() {
        sys(exec, LEASES, IEnclaveLease::assignAttestationsCall { epoch, members: vec![] })?;
        return Ok(());
    }
    let mut pool = view(exec, CONSENSUS, IConsensusRegistry::committeeCall { epoch })?.ids;
    if pool.is_empty() {
        pool = view(exec, STAKING, IStakingManager::snapshotCall { minAge: 0 })?.ids;
    }
    if pool.is_empty() {
        return Ok(());
    }
    let seed = alloy_primitives::keccak256(
        [seed(parent).as_slice(), &epoch.to_be_bytes(), b"tee/attestations"].concat(),
    );
    let members = crate::history::draw_panel(&seed, epoch, &pool);
    sys(exec, LEASES, IEnclaveLease::assignAttestationsCall { epoch, members })?;
    Ok(())
}

fn record_audits<D: DatabaseRef>(
    exec: &mut BlockExecutor<D>,
    history: &HistoryInputs,
) -> Result<(), BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    for a in &history.audits {
        sys(
            exec,
            SWARM,
            ISwarmStorage::recordAuditCall { epoch: a.epoch, task: a.task, ok: a.passed },
        )?;
    }
    for (request, ok, machine) in &history.attestations {
        sys(
            exec,
            LEASES,
            IEnclaveLease::recordAttestationCall { r: U256::from(*request), ok: *ok, machineId: *machine },
        )?;
    }
    for (job, fault) in &history.verdicts {
        sys(
            exec,
            COMPUTE,
            IComputeMarket::recordVerdictCall { id: U256::from(*job), providerAtFault: *fault },
        )?;
    }
    Ok(())
}

fn sample<D: DatabaseRef>(
    exec: &mut BlockExecutor<D>,
    rules: &EpochRules,
    parent: &Header,
    epoch: u64,
    min_age: u64,
) -> Result<Committee, BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let snap = view(exec, STAKING, IStakingManager::snapshotCall { minAge: min_age })?;
    let mut pairs: Vec<(u32, U256)> = snap.ids.into_iter().zip(snap.stakes).collect();
    pairs.sort_by_key(|p| p.0);
    let (ids, stakes): (Vec<u32>, Vec<U256>) = pairs.into_iter().unzip();
    Ok(Committee::sample(seed(parent), epoch, &ids, &stakes, rules.committee_size))
}

/// Committee lottery seed for the epoch after next: the RANDAO mix of the last block of the
/// previous epoch.
fn seed(parent: &Header) -> B256 {
    parent.mix_hash
}
