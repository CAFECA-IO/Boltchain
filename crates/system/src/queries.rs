//! Read-only queries against committed state (for the node: committees, validator records).

use crate::{abi::*, addresses::*, committee::Committee};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolCall;
use bolt_exec::{BlockInput, ViewError, view_call};
use bolt_primitives::bls::BlsPublicKey;
use revm::{DatabaseRef, database::WrapDatabaseRef};

/// Why a query failed.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The call failed (reverted, database error, bad return data).
    #[error("query {0}: {1}")]
    Call(Address, String),
}

/// Runs a view call with raw calldata against `db`; returns the raw output.
pub fn call_raw<D: DatabaseRef>(
    db: D,
    chain_id: u64,
    to: Address,
    data: Vec<u8>,
) -> Result<Bytes, QueryError>
where
    D::Error: std::fmt::Debug,
{
    let input = BlockInput {
        chain_id,
        number: 0,
        timestamp: 0,
        beneficiary: Address::ZERO,
        gas_limit: 0,
        base_fee: 0,
        prevrandao: B256::ZERO,
    };
    view_call(WrapDatabaseRef(db), &input, to, Bytes::from(data)).map_err(|e| {
        QueryError::Call(
            to,
            match e {
                ViewError::Database(d) => format!("database: {d:?}"),
                ViewError::Reverted => "reverted".into(),
                ViewError::Evm(s) => s,
            },
        )
    })
}

/// Runs a view call against `db`.
pub fn call<D: DatabaseRef, C: SolCall>(
    db: D,
    chain_id: u64,
    to: Address,
    call: C,
) -> Result<C::Return, QueryError>
where
    D::Error: std::fmt::Debug,
{
    let input = BlockInput {
        chain_id,
        number: 0,
        timestamp: 0,
        beneficiary: Address::ZERO,
        gas_limit: 0,
        base_fee: 0,
        prevrandao: B256::ZERO,
    };
    let out = view_call(WrapDatabaseRef(db), &input, to, Bytes::from(call.abi_encode())).map_err(
        |e| {
            QueryError::Call(
                to,
                match e {
                    ViewError::Database(d) => format!("database: {d:?}"),
                    ViewError::Reverted => "reverted".into(),
                    ViewError::Evm(s) => s,
                },
            )
        },
    )?;
    C::abi_decode_returns(&out).map_err(|e| QueryError::Call(to, e.to_string()))
}

/// A committee with its members' keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCommittee {
    /// Epoch.
    pub epoch: u64,
    /// Members, weights, seats.
    pub committee: Committee,
    /// BLS public key of each member.
    pub pubkeys: Vec<BlsPublicKey>,
    /// Fee recipient of each member.
    pub fee_recipients: Vec<Address>,
}

/// The committee of `epoch`, if the state has it (written at the first block of `epoch - 1`).
pub fn committee_at<D: DatabaseRef + Copy>(
    db: D,
    chain_id: u64,
    epoch: u64,
) -> Result<Option<EpochCommittee>, QueryError>
where
    D::Error: std::fmt::Debug,
{
    let c = call(db, chain_id, CONSENSUS, IConsensusRegistry::committeeCall { epoch })?;
    if c.ids.is_empty() {
        return Ok(None);
    }
    let committee = Committee::from_parts(c.ids, c.weights, &c.seats);
    let keys = call(
        db,
        chain_id,
        STAKING,
        IStakingManager::keysOfCall { ids: committee.members.clone() },
    )?;
    let pubkeys = keys.pubkeys.chunks_exact(48).map(BlsPublicKey::from_slice).collect();
    Ok(Some(EpochCommittee { epoch, committee, pubkeys, fee_recipients: keys.recipients }))
}

/// Validator id registered for a BLS key (0 if none).
pub fn validator_id<D: DatabaseRef>(
    db: D,
    chain_id: u64,
    pubkey: &BlsPublicKey,
) -> Result<u32, QueryError>
where
    D::Error: std::fmt::Debug,
{
    call(db, chain_id, STAKING, IStakingManager::idOfPubkeyCall { h: keccak256(pubkey) })
}

/// Circulating supply.
pub fn supply<D: DatabaseRef>(db: D, chain_id: u64) -> Result<U256, QueryError>
where
    D::Error: std::fmt::Debug,
{
    call(&db, chain_id, REWARDS, IRewardDistributor::supplyCall {})
}

/// Consensus phase (PoW or PoS, ADR 0007).
pub fn phase<D: DatabaseRef>(db: D, chain_id: u64) -> Result<crate::Phase, QueryError>
where
    D::Error: std::fmt::Debug,
{
    let p = call(db, chain_id, CONSENSUS, IConsensusRegistry::phaseCall {})?;
    Ok(crate::Phase {
        checkpoint_epoch: p.checkpointScheduled.then_some(p.checkpointEpoch),
        pos_epoch: p.posScheduled.then_some(p.posEpoch),
        checkpoint_streak: p.checkpointStreak,
        streak: p.thresholdStreak,
    })
}

/// Consensus phase in the state of a block being executed.
pub(crate) fn phase_in<D: DatabaseRef>(
    exec: &mut bolt_exec::BlockExecutor<D>,
) -> Result<crate::Phase, bolt_exec::block::BlockError<D::Error>>
where
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let out = exec.view_call(CONSENSUS, IConsensusRegistry::phaseCall {}.abi_encode().into())?;
    let p = IConsensusRegistry::phaseCall::abi_decode_returns(&out)
        .map_err(|e| bolt_exec::block::BlockError::Evm(format!("decode phase: {e}")))?;
    Ok(crate::Phase {
        checkpoint_epoch: p.checkpointScheduled.then_some(p.checkpointEpoch),
        pos_epoch: p.posScheduled.then_some(p.posEpoch),
        checkpoint_streak: p.checkpointStreak,
        streak: p.thresholdStreak,
    })
}
