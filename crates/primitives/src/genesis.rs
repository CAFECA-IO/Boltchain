//! Genesis file format, validation and genesis header construction.
//!
//! Boltchain has no genesis token allocation and no privileged accounts: every account in `alloc`
//! must have a zero balance, and nobody is a validator at genesis. The chain starts with mined
//! blocks (ADR 0007); `alloc` exists only to predeploy contract code.
//!
//! Local development chains (`"dev": true`) are the exception: they may fund accounts, list
//! validators staked at genesis (PoS from block 1), lower the PoS thresholds and use a fast
//! stand-in for RandomBOLT. To keep their transactions from being replayable on Boltchain they
//! must use a chain id other than 8017.

use crate::params::*;
use alloy_consensus::{
    Header,
    constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH, KECCAK_EMPTY},
};
use alloy_eips::{
    eip2935::{HISTORY_STORAGE_ADDRESS, HISTORY_STORAGE_CODE},
    eip4788::{BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE},
    eip7685::EMPTY_REQUESTS_HASH,
};
use alloy_primitives::{Address, B64, B256, Bloom, Bytes, U256, keccak256};
use alloy_trie::{TrieAccount, root::storage_root_unhashed};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub use crate::bls::{BlsPublicKey, BlsSignature};

/// Genesis file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Genesis {
    /// Local development chain: allows funded accounts and genesis validators, forbids chain id
    /// 8017.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dev: bool,
    /// Chain parameters fixed at genesis.
    pub config: ChainConfig,
    /// Genesis timestamp (unix seconds).
    pub timestamp: u64,
    /// Header extra data, at most 32 bytes.
    #[serde(default)]
    pub extra_data: Bytes,
    /// Dev chains only: validators staked at genesis. With any, the chain runs PoS from block 1
    /// (no mining phase).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dev_validators: Vec<DevValidator>,
    /// Dev chains only: a test attestation root (P-256 public key `x ‖ y`) replacing the Intel
    /// SGX Root CA in `TeeCollateral`, so simulated TDX quotes verify (ADR 0013).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_tee_root: Option<[B256; 2]>,
    /// Predeployed contracts. Balances must be zero outside dev chains.
    #[serde(default)]
    pub alloc: BTreeMap<Address, GenesisAccount>,
}

/// Chain parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainConfig {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// PoS slot length in seconds.
    pub slot_seconds: u64,
    /// Blocks per epoch.
    pub epoch_slots: u64,
    /// Committee seats per epoch.
    pub committee_size: u32,
    /// Gas limit of the genesis block; later blocks move it by at most 1/1024 of the parent's
    /// (block producers vote), within [`GAS_LIMIT_RANGE`].
    pub gas_limit: u64,
    /// Minimum base fee in wei.
    pub min_base_fee_wei: u64,
    /// Mining phase.
    #[serde(default)]
    pub pow: PowConfig,
    /// Dev chains only: stake-finality (phase B) threshold on the number of stakers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_min_stakers: Option<u32>,
    /// Dev chains only: stake-finality threshold on total stake, in whole BOLT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_min_stake_bolt: Option<u64>,
    /// Dev chains only: depth at which mined blocks become checkpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_depth: Option<u64>,
    /// Dev chains only: epochs of history every validator keeps (older ones are sharded and
    /// audited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_recent_epochs: Option<u64>,
    /// Dev chains only: PoS threshold on the number of stakers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pos_min_stakers: Option<u32>,
    /// Dev chains only: PoS threshold on total stake, in whole BOLT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pos_min_stake_bolt: Option<u64>,
    /// Dev chains only: epochs the thresholds must hold (at most 14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pos_streak_epochs: Option<u64>,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID,
            slot_seconds: SLOT_SECONDS,
            epoch_slots: EPOCH_SLOTS,
            committee_size: MIN_COMMITTEE_SIZE,
            gas_limit: DEFAULT_GAS_LIMIT,
            min_base_fee_wei: MIN_BASE_FEE_WEI,
            pow: PowConfig::default(),
            checkpoint_min_stakers: None,
            checkpoint_min_stake_bolt: None,
            checkpoint_depth: None,
            history_recent_epochs: None,
            pos_min_stakers: None,
            pos_min_stake_bolt: None,
            pos_streak_epochs: None,
        }
    }
}

impl ChainConfig {
    /// Stake-finality thresholds: (stakers, total stake in whole BOLT).
    pub fn checkpoint_thresholds(&self) -> (u32, u64) {
        (
            self.checkpoint_min_stakers.unwrap_or(CHECKPOINT_MIN_STAKERS),
            self.checkpoint_min_stake_bolt.unwrap_or(CHECKPOINT_MIN_TOTAL_STAKE_BOLT),
        )
    }

    /// Epochs of history every validator keeps.
    pub fn history_recent_epochs(&self) -> u64 {
        self.history_recent_epochs.unwrap_or(RECENT_PINNED_EPOCHS)
    }

    /// Checkpoint depth.
    pub fn checkpoint_depth(&self) -> u64 {
        self.checkpoint_depth.unwrap_or(CHECKPOINT_DEPTH)
    }

    /// PoS thresholds: (stakers, total stake in whole BOLT, streak in epochs).
    pub fn pos_thresholds(&self) -> (u32, u64, u64) {
        (
            self.pos_min_stakers.unwrap_or(POS_MIN_STAKERS),
            self.pos_min_stake_bolt.unwrap_or(POS_MIN_TOTAL_STAKE_BOLT),
            self.pos_streak_epochs.unwrap_or(POS_STREAK_EPOCHS),
        )
    }
}

/// Proof-of-work algorithm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PowAlgorithm {
    /// RandomX with Boltchain parameters (the only one allowed outside dev chains).
    #[default]
    RandomBolt,
    /// keccak256: a fast stand-in for tests on dev chains.
    Keccak,
}

/// Mining-phase parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PowConfig {
    /// Algorithm.
    #[serde(default)]
    pub algorithm: PowAlgorithm,
    /// Difficulty of blocks 1 and 2.
    pub initial_difficulty: U256,
    /// Target block spacing, in seconds.
    pub block_seconds: u64,
    /// ASERT half-life, in seconds.
    pub half_life_seconds: u64,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            algorithm: PowAlgorithm::RandomBolt,
            initial_difficulty: U256::from(POW_INITIAL_DIFFICULTY),
            block_seconds: POW_BLOCK_SECONDS,
            half_life_seconds: POW_HALF_LIFE_SECONDS,
        }
    }
}

/// A validator staked at genesis (dev chains only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevValidator {
    /// Name, for humans.
    pub name: String,
    /// BLS12-381 public key used for votes and RANDAO reveals.
    pub bls_pubkey: BlsPublicKey,
    /// Proof of possession of the BLS key (rules out rogue-key attacks on aggregate signatures).
    pub proof_of_possession: BlsSignature,
    /// Owner of the stake.
    pub owner: Address,
    /// Receives rewards and tips.
    pub fee_recipient: Address,
    /// Stake, in whole BOLT (at least the minimum stake).
    pub stake_bolt: u64,
}

/// A predeployed account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenesisAccount {
    /// Account nonce.
    #[serde(default)]
    pub nonce: u64,
    /// Balance. Must be zero: Boltchain has no genesis allocation.
    #[serde(default)]
    pub balance: U256,
    /// Contract code.
    #[serde(default)]
    pub code: Bytes,
    /// Initial storage.
    #[serde(default)]
    pub storage: BTreeMap<B256, B256>,
}

impl GenesisAccount {
    /// The account as stored in the state trie.
    pub fn trie_account(&self) -> TrieAccount {
        let storage = self
            .storage
            .iter()
            .filter(|(_, v)| !v.is_zero())
            .map(|(k, v)| (*k, U256::from_be_bytes(v.0)));
        TrieAccount {
            nonce: self.nonce,
            balance: self.balance,
            storage_root: storage_root_unhashed(storage),
            code_hash: if self.code.is_empty() { KECCAK_EMPTY } else { keccak256(&self.code) },
        }
    }
}

/// Reasons a genesis file is rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenesisError {
    #[error("chain id must be {CHAIN_ID}, got {0}")]
    ChainId(u64),
    #[error("dev chains must not use chain id {CHAIN_ID}")]
    DevChainId,
    #[error("slot/epoch length must be {SLOT_SECONDS}s/{EPOCH_SLOTS} slots")]
    SlotTiming,
    #[error("committee size {0} is below the floor of {MIN_COMMITTEE_SIZE}")]
    CommitteeTooSmall(u32),
    #[error("gas limit {0} outside allowed range")]
    GasLimit(u64),
    #[error("min base fee {0} below protocol floor {MIN_BASE_FEE_WEI}")]
    BaseFee(u64),
    #[error("extra data is {0} bytes, max 32")]
    ExtraData(usize),
    #[error(
        "mining parameters must be RandomBOLT, {POW_BLOCK_SECONDS}s spacing, {POW_HALF_LIFE_SECONDS}s half-life"
    )]
    Pow,
    #[error("initial difficulty must be positive")]
    Difficulty,
    #[error("duplicate or invalid BLS public key: {0}")]
    BadValidatorKey(BlsPublicKey),
    #[error("invalid proof of possession for BLS key {0}")]
    BadPossession(BlsPublicKey),
    #[error("genesis validator stake below the minimum")]
    ValidatorStake,
    #[error("no genesis allocation: account {0} has a non-zero balance")]
    NonZeroBalance(Address),
    #[error("genesis validators and PoS threshold overrides are for dev chains only")]
    DevOnly,
    #[error("PoS streak must be between 1 and {POS_STREAK_EPOCHS} epochs")]
    Streak,
    #[error("stake-finality thresholds must not exceed the PoS thresholds, depth at least 1")]
    Checkpoints,
    #[error("account {0} is a protocol predeploy and cannot be overridden")]
    ReservedAddress(Address),
}

impl Genesis {
    /// Parses and validates a genesis JSON document.
    pub fn from_json(json: &str) -> Result<Self, GenesisLoadError> {
        let genesis: Self = serde_json::from_str(json)?;
        genesis.validate()?;
        Ok(genesis)
    }

    /// Checks every protocol rule a genesis must satisfy.
    pub fn validate(&self) -> Result<(), GenesisError> {
        let c = &self.config;
        if self.dev && c.chain_id == CHAIN_ID {
            return Err(GenesisError::DevChainId);
        }
        if !self.dev && c.chain_id != CHAIN_ID {
            return Err(GenesisError::ChainId(c.chain_id));
        }
        if self.dev {
            // Dev chains may use short epochs, small committees and low thresholds (vote counters
            // are 16-bit per epoch, committees at most 4096 seats).
            if c.slot_seconds == 0 || !(2..=65_535).contains(&c.epoch_slots) {
                return Err(GenesisError::SlotTiming);
            }
            if !(1..=4096).contains(&c.committee_size) {
                return Err(GenesisError::CommitteeTooSmall(c.committee_size));
            }
            if c.pow.block_seconds == 0 || c.pow.half_life_seconds == 0 {
                return Err(GenesisError::Pow);
            }
            if !(1..=POS_STREAK_EPOCHS).contains(&c.pos_thresholds().2) {
                return Err(GenesisError::Streak);
            }
        } else {
            if c.slot_seconds != SLOT_SECONDS || c.epoch_slots != EPOCH_SLOTS {
                return Err(GenesisError::SlotTiming);
            }
            if c.committee_size < MIN_COMMITTEE_SIZE || c.committee_size > 4096 {
                return Err(GenesisError::CommitteeTooSmall(c.committee_size));
            }
            if c.pos_min_stakers.is_some()
                || c.pos_min_stake_bolt.is_some()
                || c.checkpoint_min_stakers.is_some()
                || c.checkpoint_min_stake_bolt.is_some()
                || c.checkpoint_depth.is_some()
                || c.history_recent_epochs.is_some()
                || c.pos_streak_epochs.is_some()
                || !self.dev_validators.is_empty()
                || self.dev_tee_root.is_some()
            {
                return Err(GenesisError::DevOnly);
            }
            if c.pow.algorithm != PowAlgorithm::RandomBolt
                || c.pow.block_seconds != POW_BLOCK_SECONDS
                || c.pow.half_life_seconds != POW_HALF_LIFE_SECONDS
            {
                return Err(GenesisError::Pow);
            }
        }
        if c.pow.initial_difficulty.is_zero() {
            return Err(GenesisError::Difficulty);
        }
        let (t1_stakers, t1_stake) = c.checkpoint_thresholds();
        let (t2_stakers, t2_stake, _) = c.pos_thresholds();
        if t1_stakers > t2_stakers || t1_stake > t2_stake || c.checkpoint_depth() == 0 {
            return Err(GenesisError::Checkpoints);
        }
        if c.gas_limit < GAS_LIMIT_RANGE.0 || c.gas_limit > GAS_LIMIT_RANGE.1 {
            return Err(GenesisError::GasLimit(c.gas_limit));
        }
        if c.min_base_fee_wei < MIN_BASE_FEE_WEI {
            return Err(GenesisError::BaseFee(c.min_base_fee_wei));
        }
        if self.extra_data.len() > 32 {
            return Err(GenesisError::ExtraData(self.extra_data.len()));
        }

        let mut keys = BTreeSet::new();
        for v in &self.dev_validators {
            if !crate::bls::is_valid_public_key(&v.bls_pubkey) || !keys.insert(v.bls_pubkey) {
                return Err(GenesisError::BadValidatorKey(v.bls_pubkey));
            }
            if !crate::bls::verify_possession(&v.bls_pubkey, &v.proof_of_possession) {
                return Err(GenesisError::BadPossession(v.bls_pubkey));
            }
            if (v.stake_bolt as u128) * WEI_PER_BOLT < MIN_STAKE_WEI {
                return Err(GenesisError::ValidatorStake);
            }
        }

        for (addr, acc) in &self.alloc {
            if !self.dev && !acc.balance.is_zero() {
                return Err(GenesisError::NonZeroBalance(*addr));
            }
            // Protocol predeploys and the system contract range 0xB017000000000000000000000000000000xxxx.
            let system = addr[0] == 0xb0 && addr[1] == 0x17 && addr[2..18].iter().all(|b| *b == 0);
            if protocol_predeploys().contains_key(addr) || system {
                return Err(GenesisError::ReservedAddress(*addr));
            }
        }
        Ok(())
    }

    /// Whether the chain starts with mined blocks (no genesis validators).
    pub fn starts_with_pow(&self) -> bool {
        self.dev_validators.is_empty()
    }

    /// `alloc` plus the protocol predeploys every Osaka chain needs (EIP-4788, EIP-2935).
    pub fn effective_alloc(&self) -> BTreeMap<Address, GenesisAccount> {
        let mut all = self.alloc.clone();
        all.extend(protocol_predeploys());
        all
    }

    /// Initial randomness seed: keccak of the chain id, timestamp and extra data (nobody can
    /// choose it after the genesis file is published).
    pub fn initial_seed(&self) -> B256 {
        keccak256(
            [
                b"boltchain/genesis-seed".as_slice(),
                &self.config.chain_id.to_be_bytes(),
                &self.timestamp.to_be_bytes(),
                &self.extra_data,
            ]
            .concat(),
        )
    }

    /// The genesis block header for a given state root, with every Osaka-era field populated. The
    /// state root depends on the system contracts, computed by `bolt_system::genesis_header`.
    pub fn header_with_state_root(&self, state_root: B256) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: Address::ZERO,
            state_root,
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            logs_bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            number: 0,
            gas_limit: self.config.gas_limit,
            gas_used: 0,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            mix_hash: self.initial_seed(),
            nonce: B64::ZERO,
            base_fee_per_gas: Some(self.config.min_base_fee_wei),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            // Carries the parent QC hash on later blocks; genesis has no parent.
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
            // Amsterdam fields: not part of Osaka.
            block_access_list_hash: None,
            slot_number: None,
        }
    }
}

/// Protocol-level predeploys, identical to Ethereum mainnet deployments.
pub fn protocol_predeploys() -> BTreeMap<Address, GenesisAccount> {
    let acc = |code: &Bytes| GenesisAccount { nonce: 1, code: code.clone(), ..Default::default() };
    BTreeMap::from([
        (BEACON_ROOTS_ADDRESS, acc(&BEACON_ROOTS_CODE)),
        (HISTORY_STORAGE_ADDRESS, acc(&HISTORY_STORAGE_CODE)),
    ])
}

/// Error loading a genesis file.
#[derive(Debug, thiserror::Error)]
pub enum GenesisLoadError {
    #[error("invalid genesis JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid genesis: {0}")]
    Invalid(#[from] GenesisError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn sample() -> Genesis {
        Genesis {
            dev: false,
            config: ChainConfig::default(),
            timestamp: 1_800_000_000,
            extra_data: Bytes::from_static(b"Boltchain"),
            dev_validators: vec![],
            dev_tee_root: None,
            alloc: BTreeMap::new(),
        }
    }

    fn dev_validator(i: u32) -> DevValidator {
        let k = crate::bls::dev_key(i);
        DevValidator {
            name: format!("v{i}"),
            bls_pubkey: k.public_key(),
            proof_of_possession: k.proof_of_possession(),
            owner: Address::repeat_byte(i as u8 + 1),
            fee_recipient: Address::repeat_byte(i as u8 + 1),
            stake_bolt: 1_000,
        }
    }

    fn dev() -> Genesis {
        let mut g = sample();
        g.dev = true;
        g.config.chain_id = 1337;
        g
    }

    #[test]
    fn genesis_validators_are_dev_only_and_checked() {
        let mut g = sample();
        g.dev_validators = vec![dev_validator(0)];
        assert_eq!(g.validate(), Err(GenesisError::DevOnly));

        let mut g = dev();
        g.dev_validators = (0..4).map(dev_validator).collect();
        g.validate().unwrap();
        assert!(!g.starts_with_pow());

        g.dev_validators[2].proof_of_possession = g.dev_validators[3].proof_of_possession;
        assert!(matches!(g.validate(), Err(GenesisError::BadPossession(_))));

        let mut g = dev();
        g.dev_validators = vec![dev_validator(0), dev_validator(0)];
        assert!(matches!(g.validate(), Err(GenesisError::BadValidatorKey(_))));

        let mut g = dev();
        g.dev_validators = vec![dev_validator(0)];
        g.dev_validators[0].stake_bolt = 63;
        assert_eq!(g.validate(), Err(GenesisError::ValidatorStake));
    }

    #[test]
    fn sample_is_valid_and_hash_is_stable() {
        let g = sample();
        g.validate().unwrap();
        assert!(g.starts_with_pow());
        let root = B256::repeat_byte(1);
        assert_eq!(
            g.header_with_state_root(root).hash_slow(),
            g.clone().header_with_state_root(root).hash_slow()
        );
        let h = g.header_with_state_root(root);
        assert_eq!(h.requests_hash, Some(EMPTY_REQUESTS_HASH));
        assert_eq!(h.withdrawals_root, Some(EMPTY_ROOT_HASH));
    }

    #[test]
    fn json_roundtrip() {
        let g = sample();
        let json = serde_json::to_string_pretty(&g).unwrap();
        assert_eq!(Genesis::from_json(&json).unwrap(), g);
        let mut g = dev();
        g.dev_validators = vec![dev_validator(1)];
        g.config.pow.algorithm = PowAlgorithm::Keccak;
        let json = serde_json::to_string_pretty(&g).unwrap();
        assert_eq!(Genesis::from_json(&json).unwrap(), g);
    }

    #[test]
    fn rejects_genesis_allocation() {
        let mut g = sample();
        let a = address!("00000000000000000000000000000000000000aa");
        g.alloc.insert(a, GenesisAccount { balance: U256::from(1), ..Default::default() });
        assert_eq!(g.validate(), Err(GenesisError::NonZeroBalance(a)));
    }

    #[test]
    fn dev_chains_may_fund_accounts_but_not_use_8017() {
        let mut g = sample();
        g.dev = true;
        g.alloc.insert(
            Address::repeat_byte(0xaa),
            GenesisAccount { balance: U256::from(1), ..Default::default() },
        );
        assert_eq!(g.validate(), Err(GenesisError::DevChainId));
        g.config.chain_id = 1337;
        g.validate().unwrap();
    }

    #[test]
    fn rejects_rule_violations() {
        let mut g = sample();
        g.config.chain_id = 1;
        assert_eq!(g.validate(), Err(GenesisError::ChainId(1)));

        let mut g = sample();
        g.config.committee_size = 511;
        assert!(matches!(g.validate(), Err(GenesisError::CommitteeTooSmall(511))));

        let mut g = sample();
        g.config.pos_min_stakers = Some(1);
        assert_eq!(g.validate(), Err(GenesisError::DevOnly));

        let mut g = sample();
        g.config.pow.algorithm = PowAlgorithm::Keccak;
        assert_eq!(g.validate(), Err(GenesisError::Pow));

        let mut g = sample();
        g.config.pow.block_seconds = 6;
        assert_eq!(g.validate(), Err(GenesisError::Pow));

        let mut g = sample();
        g.config.pow.initial_difficulty = U256::ZERO;
        assert_eq!(g.validate(), Err(GenesisError::Difficulty));

        let mut g = dev();
        g.config.pos_streak_epochs = Some(15);
        assert_eq!(g.validate(), Err(GenesisError::Streak));

        let mut g = dev();
        g.config.pos_min_stakers = Some(4);
        assert_eq!(g.validate(), Err(GenesisError::Checkpoints), "T1 above T2");
        g.config.checkpoint_min_stakers = Some(2);
        g.validate().unwrap();

        let mut g = sample();
        g.config.checkpoint_depth = Some(3);
        assert_eq!(g.validate(), Err(GenesisError::DevOnly));

        let mut g = sample();
        g.alloc.insert(BEACON_ROOTS_ADDRESS, GenesisAccount::default());
        assert_eq!(g.validate(), Err(GenesisError::ReservedAddress(BEACON_ROOTS_ADDRESS)));
    }

    /// The mainnet template is complete except for the launch timestamp: no validators, no
    /// multisig, no allocation.
    #[test]
    fn mainnet_template_is_valid() {
        let g: Genesis =
            serde_json::from_str(include_str!("../../../genesis/mainnet.template.json")).unwrap();
        g.validate().unwrap();
        assert!(g.starts_with_pow());
        assert!(g.alloc.is_empty());
        assert_eq!(g.config, ChainConfig::default());
    }

    #[test]
    fn storage_affects_the_trie_account() {
        let mut acc = GenesisAccount { code: Bytes::from_static(&[0x00]), ..Default::default() };
        assert_eq!(acc.trie_account().storage_root, EMPTY_ROOT_HASH);
        acc.storage.insert(B256::ZERO, B256::with_last_byte(1));
        assert_ne!(acc.trie_account().storage_root, EMPTY_ROOT_HASH);
    }
}
