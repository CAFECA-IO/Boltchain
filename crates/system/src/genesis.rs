//! Genesis state: the user `alloc`, the Osaka protocol predeploys, and the Boltchain system
//! contracts deployed at fixed addresses (ADR 0006 §7, ADR 0008: immutable, no governance).
//!
//! Deployment runs each contract's init code *at its final address* (the account's code is set to
//! the init code and called as the system address), so `address(this)`, storage written by the
//! constructor and immutables are all correct. The returned runtime code then replaces the init
//! code. Initialisation calls (dev-chain validators, supply) follow, also from the system address
//! at block 0.

use crate::{abi::*, addresses::*, artifacts};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolCall;
use alloy_trie::root::state_root_unhashed;
use bolt_primitives::{Genesis, genesis::GenesisAccount, params::WEI_PER_BOLT};
use revm::{
    Context, MainBuilder, MainContext, SystemCallCommitEvm,
    bytecode::Bytecode,
    context::result::ExecutionResult,
    database::{CacheDB, EmptyDB},
    state::AccountInfo,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Mutex, OnceLock},
};

/// Why the genesis state could not be built.
#[derive(Debug, thiserror::Error)]
pub enum GenesisBuildError {
    /// A constructor or initialisation call failed.
    #[error("genesis call to {0} failed: {1}")]
    Call(Address, String),
}

struct Builder {
    db: CacheDB<EmptyDB>,
    chain_id: u64,
    timestamp: u64,
}

impl Builder {
    fn run(&mut self, to: Address, data: Bytes) -> Result<Bytes, GenesisBuildError> {
        let mut block = revm::context::BlockEnv {
            number: U256::ZERO,
            timestamp: U256::from(self.timestamp),
            ..Default::default()
        };
        block.prevrandao = Some(B256::ZERO);
        let mut evm = Context::mainnet()
            .with_db(&mut self.db)
            .with_cfg(bolt_exec::cfg_env(self.chain_id))
            .with_block(block)
            .build_mainnet();
        match evm.system_call_commit(to, data) {
            Ok(ExecutionResult::Success { output, .. }) => Ok(output.into_data()),
            Ok(other) => Err(GenesisBuildError::Call(to, format!("{other:?}"))),
            Err(e) => Err(GenesisBuildError::Call(to, format!("{e:?}"))),
        }
    }

    /// Runs `initcode ‖ args` at `addr` and installs the returned runtime code there.
    fn deploy(
        &mut self,
        addr: Address,
        initcode: &Bytes,
        args: &[u8],
    ) -> Result<(), GenesisBuildError> {
        let init = Bytecode::new_raw([initcode.as_ref(), args].concat().into());
        self.db.insert_account_info(
            addr,
            AccountInfo {
                nonce: 1,
                code_hash: init.hash_slow(),
                code: Some(init),
                ..Default::default()
            },
        );
        let runtime = self.run(addr, Bytes::new())?;
        let code = Bytecode::new_raw(runtime);
        let mut info = self.db.load_account(addr).map(|a| a.info.clone()).unwrap_or_default();
        info.code_hash = code.hash_slow();
        info.code = Some(code);
        info.nonce = 1;
        self.db.insert_account_info(addr, info);
        Ok(())
    }

    fn call<C: SolCall>(&mut self, to: Address, call: C) -> Result<C::Return, GenesisBuildError> {
        let out = self.run(to, call.abi_encode().into())?;
        C::abi_decode_returns(&out).map_err(|e| GenesisBuildError::Call(to, e.to_string()))
    }

    fn into_alloc(self) -> BTreeMap<Address, GenesisAccount> {
        let mut out = BTreeMap::new();
        for (addr, acc) in self.db.cache.accounts {
            let code = match &acc.info.code {
                Some(c) if !c.is_empty() => c.original_bytes(),
                _ => self
                    .db
                    .cache
                    .contracts
                    .get(&acc.info.code_hash)
                    .map(|c| c.original_bytes())
                    .unwrap_or_default(),
            };
            let storage: BTreeMap<B256, B256> = acc
                .storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (B256::from(*k), B256::from(*v)))
                .collect();
            if acc.info.nonce == 0
                && acc.info.balance.is_zero()
                && code.is_empty()
                && storage.is_empty()
            {
                continue; // e.g. the system address touched by calls
            }
            out.insert(
                addr,
                GenesisAccount { nonce: acc.info.nonce, balance: acc.info.balance, code, storage },
            );
        }
        out
    }
}

fn build(g: &Genesis) -> Result<BTreeMap<Address, GenesisAccount>, GenesisBuildError> {
    let mut b = Builder {
        db: CacheDB::new(EmptyDB::default()),
        chain_id: g.config.chain_id,
        timestamp: g.timestamp,
    };
    let mut supply = U256::ZERO;
    for (addr, acc) in g.effective_alloc() {
        supply += acc.balance;
        let mut info = AccountInfo { nonce: acc.nonce, balance: acc.balance, ..Default::default() };
        if !acc.code.is_empty() {
            let code = Bytecode::new_raw(acc.code.clone());
            info.code_hash = code.hash_slow();
            info.code = Some(code);
        }
        b.db.insert_account_info(addr, info);
        for (k, v) in &acc.storage {
            b.db.insert_account_storage(addr, U256::from_be_bytes(k.0), U256::from_be_bytes(v.0))
                .expect("cache db");
        }
    }

    b.deploy(STAKING, &artifacts::staking_manager().bytecode, &[])?;
    b.deploy(CONSENSUS, &artifacts::consensus_registry().bytecode, &[])?;
    b.deploy(REWARDS, &artifacts::reward_distributor().bytecode, &[])?;
    // ADR 0014; the public testnet started with HistoryRegistry and gets SwarmStorage at its
    // `swarm` fork.
    if bolt_primitives::forks::active(g.config.chain_id, bolt_primitives::forks::SWARM, 0) {
        b.deploy(SWARM, &artifacts::swarm_storage().bytecode, &[])?;
    } else {
        let init = Bytes::from_static(bolt_primitives::forks::TESTNET_GENESIS_HISTORY_REGISTRY);
        b.deploy(SWARM, &init, &[])?;
    }
    // ADR 0011. The public testnet keeps the version its genesis was built with; it gets the
    // current one at its `tee` fork.
    if g.config.chain_id == bolt_primitives::forks::TESTNET_CHAIN_ID {
        let init = Bytes::from_static(bolt_primitives::forks::TESTNET_GENESIS_COMPUTE_MARKET);
        b.deploy(COMPUTE, &init, &[])?;
    } else {
        b.deploy(COMPUTE, &artifacts::compute_market().bytecode, &[])?;
    }
    // ADR 0011 §7 and ADR 0013; the public testnet gets them at its `tee` fork.
    if bolt_primitives::forks::active(g.config.chain_id, bolt_primitives::forks::TEE, 0) {
        b.deploy(MODELS, &artifacts::model_registry().bytecode, &[])?;
        b.deploy(IMAGES, &artifacts::image_registry().bytecode, &[])?;
        b.deploy(COLLATERAL, &artifacts::tee_collateral().bytecode, &[])?;
        b.deploy(TDX, &artifacts::tdx_verifier().bytecode, &[])?;
        b.deploy(LEASES, &artifacts::enclave_lease().bytecode, &[])?;
        b.deploy(WALLET, &artifacts::limited_wallet().bytecode, &[])?;
        if let Some([x, y]) = g.dev_tee_root {
            b.call(COLLATERAL, ITeeCollateral::initDevRootCall { x, y })?;
        }
    }

    // Dev chains: validators staked at genesis and their committee for epoch 0 (one seat each);
    // PoS from block 1. Their stake is part of the genesis supply.
    if !g.dev_validators.is_empty() {
        let mut ids = Vec::new();
        let mut staked = U256::ZERO;
        for v in &g.dev_validators {
            let stake = U256::from(v.stake_bolt) * U256::from(WEI_PER_BOLT);
            let id = b.call(
                STAKING,
                IStakingManager::registerGenesisCall {
                    pubkey: Bytes::copy_from_slice(v.bls_pubkey.as_slice()),
                    owner: v.owner,
                    feeRecipient: v.fee_recipient,
                    stake,
                },
            )?;
            ids.push(id);
            staked += stake;
        }
        let mut info = b.db.load_account(STAKING).map(|a| a.info.clone()).unwrap_or_default();
        info.balance += staked;
        b.db.insert_account_info(STAKING, info);
        supply += staked;
        let committee = crate::committee::Committee::equal(&ids);
        b.call(
            CONSENSUS,
            IConsensusRegistry::initializeCall {
                memberIds: committee.members.clone(),
                weights: committee.weights.clone(),
                seats: committee.seats_bytes(),
            },
        )?;
    }
    b.call(REWARDS, IRewardDistributor::initializeCall { genesisSupply: supply })?;
    Ok(b.into_alloc())
}

fn cache() -> &'static Mutex<HashMap<B256, BTreeMap<Address, GenesisAccount>>> {
    static C: OnceLock<Mutex<HashMap<B256, BTreeMap<Address, GenesisAccount>>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// The complete genesis state (cached per genesis file).
pub fn genesis_alloc(g: &Genesis) -> Result<BTreeMap<Address, GenesisAccount>, GenesisBuildError> {
    let key = keccak256(serde_json::to_vec(g).expect("genesis serializes"));
    if let Some(a) = cache().lock().expect("genesis cache").get(&key) {
        return Ok(a.clone());
    }
    let alloc = build(g)?;
    cache().lock().expect("genesis cache").insert(key, alloc.clone());
    Ok(alloc)
}

/// Genesis state root.
pub fn genesis_state_root(g: &Genesis) -> Result<B256, GenesisBuildError> {
    Ok(state_root_unhashed(genesis_alloc(g)?.iter().map(|(a, acc)| (*a, acc.trie_account()))))
}

/// The genesis header.
pub fn genesis_header(g: &Genesis) -> Result<Header, GenesisBuildError> {
    Ok(g.header_with_state_root(genesis_state_root(g)?))
}

/// The genesis block hash.
pub fn genesis_hash(g: &Genesis) -> Result<B256, GenesisBuildError> {
    Ok(genesis_header(g)?.hash_slow())
}
