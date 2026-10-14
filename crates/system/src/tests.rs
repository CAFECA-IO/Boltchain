//! Contract tests on an in-memory revm database built from the genesis state.

use crate::{abi::*, addresses::*, artifacts, genesis_alloc};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_sol_types::SolCall;
use bolt_primitives::{
    Genesis,
    bls::{self, BlsSecretKey, dev_key, pubkey_point, signature_point},
};
use revm::{
    Context, ExecuteCommitEvm, MainBuilder, MainContext, SystemCallCommitEvm,
    bytecode::Bytecode,
    context::{BlockEnv, TxEnv, result::ExecutionResult},
    database::{CacheDB, EmptyDB},
    state::AccountInfo,
};

pub(crate) struct Evm {
    pub db: CacheDB<EmptyDB>,
    pub chain_id: u64,
    pub number: u64,
    pub timestamp: u64,
}

impl Evm {
    pub fn from_genesis(g: &Genesis) -> Self {
        let mut db = CacheDB::new(EmptyDB::default());
        for (a, acc) in genesis_alloc(g).unwrap() {
            let mut info =
                AccountInfo { nonce: acc.nonce, balance: acc.balance, ..Default::default() };
            if !acc.code.is_empty() {
                let c = Bytecode::new_raw(acc.code.clone());
                info.code_hash = c.hash_slow();
                info.code = Some(c);
            }
            db.insert_account_info(a, info);
            for (k, v) in acc.storage {
                db.insert_account_storage(a, U256::from_be_bytes(k.0), U256::from_be_bytes(v.0))
                    .unwrap();
            }
        }
        Self { db, chain_id: g.config.chain_id, number: 1, timestamp: g.timestamp }
    }

    fn block(&self) -> BlockEnv {
        BlockEnv {
            number: U256::from(self.number),
            timestamp: U256::from(self.timestamp),
            basefee: 0,
            gas_limit: 1 << 40,
            ..Default::default()
        }
    }

    pub fn fund(&mut self, a: Address, wei: U256) {
        let mut info = self.db.load_account(a).unwrap().info.clone();
        info.balance += wei;
        self.db.insert_account_info(a, info);
    }

    pub fn balance(&mut self, a: Address) -> U256 {
        self.db.load_account(a).unwrap().info.balance
    }

    /// A transaction; returns (success, output).
    pub fn tx(&mut self, from: Address, to: Address, value: U256, data: Vec<u8>) -> (bool, Bytes) {
        let (ok, out, _) = self.tx_gas(from, to, value, data);
        (ok, out)
    }

    /// A transaction; returns (success, output, gas used).
    pub fn tx_gas(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
        data: Vec<u8>,
    ) -> (bool, Bytes, u64) {
        let nonce = self.db.load_account(from).map(|a| a.info.nonce).unwrap_or(0);
        let block = self.block();
        let mut cfg = bolt_exec::cfg_env(self.chain_id);
        cfg.tx_gas_limit_cap = Some(1 << 30);
        let mut evm = Context::mainnet()
            .with_db(&mut self.db)
            .with_cfg(cfg)
            .with_block(block)
            .build_mainnet();
        let tx = TxEnv {
            caller: from,
            kind: TxKind::Call(to),
            value,
            data: data.into(),
            gas_limit: 50_000_000,
            gas_price: 0,
            nonce,
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let r = evm.transact_commit(tx).unwrap();
        let gas = r.tx_gas_used();
        match r {
            ExecutionResult::Success { output, .. } => (true, output.into_data(), gas),
            ExecutionResult::Revert { output, .. } => (false, output, gas),
            other => panic!("halted: {other:?}"),
        }
    }

    pub fn call<C: SolCall>(&mut self, from: Address, to: Address, value: U256, c: C) -> C::Return {
        let (ok, out) = self.tx(from, to, value, c.abi_encode());
        assert!(ok, "call to {to} reverted: {out}");
        C::abi_decode_returns(&out).unwrap()
    }

    pub fn try_call<C: SolCall>(&mut self, from: Address, to: Address, value: U256, c: C) -> bool {
        self.tx(from, to, value, c.abi_encode()).0
    }

    pub fn view<C: SolCall>(&mut self, to: Address, c: C) -> C::Return {
        crate::queries::call(&self.db, self.chain_id, to, c).unwrap()
    }

    pub fn system<C: SolCall>(&mut self, to: Address, c: C) -> C::Return {
        let block = self.block();
        let mut evm = Context::mainnet()
            .with_db(&mut self.db)
            .with_cfg(bolt_exec::cfg_env(self.chain_id))
            .with_block(block)
            .build_mainnet();
        match evm.system_call_commit(to, c.abi_encode().into()).unwrap() {
            ExecutionResult::Success { output, .. } => {
                C::abi_decode_returns(&output.into_data()).unwrap()
            }
            other => panic!("system call failed: {other:?}"),
        }
    }

    pub fn deploy_at(&mut self, a: Address, runtime: &Bytes) {
        let c = Bytecode::new_raw(runtime.clone());
        self.db.insert_account_info(
            a,
            AccountInfo { nonce: 1, code_hash: c.hash_slow(), code: Some(c), ..Default::default() },
        );
    }
}

pub(crate) fn dev_genesis() -> Genesis {
    Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap()
}

fn bytes(b: &[u8]) -> Bytes {
    Bytes::copy_from_slice(b)
}

#[test]
fn solidity_bls_matches_blst() {
    let mut evm = Evm::from_genesis(&dev_genesis());
    let harness = Address::repeat_byte(0x42);
    evm.deploy_at(harness, &artifacts::bls_harness().deployed);
    let me = Address::repeat_byte(1);
    for i in 0..3u32 {
        let sk = dev_key(i);
        let pk = sk.public_key();
        let pkp = pubkey_point(&pk).unwrap();
        // compression matches blst's
        let c = evm.view(harness, IBLSHarness::compressCall { pk: bytes(&pkp) });
        assert_eq!(c.as_ref(), pk.as_slice());
        // signature over a message
        let msg = format!("boltchain test message {i}").into_bytes();
        let sig = sk.sign(&msg);
        let sp = signature_point(&sig).unwrap();
        assert!(evm.view(
            harness,
            IBLSHarness::verifyCall { pk: bytes(&pkp), message: bytes(&msg), sig: bytes(&sp) }
        ));
        assert!(!evm.view(
            harness,
            IBLSHarness::verifyCall { pk: bytes(&pkp), message: bytes(b"other"), sig: bytes(&sp) }
        ));
        let other = pubkey_point(&dev_key(i + 10).public_key()).unwrap();
        assert!(!evm.view(
            harness,
            IBLSHarness::verifyCall { pk: bytes(&other), message: bytes(&msg), sig: bytes(&sp) }
        ));
        // proof of possession uses the PoP DST
        let pop = signature_point(&sk.proof_of_possession()).unwrap();
        assert!(evm.view(
            harness,
            IBLSHarness::verifyPopCall {
                pk: bytes(&pkp),
                pubkey: bytes(pk.as_slice()),
                pop: bytes(&pop)
            }
        ));
        assert!(!evm.view(
            harness,
            IBLSHarness::verifyCall {
                pk: bytes(&pkp),
                message: bytes(pk.as_slice()),
                sig: bytes(&pop)
            }
        ));
    }
    // gas of one verification, as a transaction
    let sk = BlsSecretKey::from_ikm(&[9u8; 32]).unwrap();
    let pkp = pubkey_point(&sk.public_key()).unwrap();
    let sp = signature_point(&sk.sign(b"gas")).unwrap();
    let (ok, _) = evm.tx(
        me,
        harness,
        U256::ZERO,
        IBLSHarness::verifyCall { pk: bytes(&pkp), message: bytes(b"gas"), sig: bytes(&sp) }
            .abi_encode(),
    );
    assert!(ok);
    assert!(bls::verify(&sk.public_key(), b"gas", &sk.sign(b"gas")));
}

#[test]
fn genesis_deploys_system_contracts() {
    // Dev chain with genesis validators: PoS from the start.
    let g = dev_genesis();
    let mut evm = Evm::from_genesis(&g);
    let n = g.dev_validators.len() as u32;
    let c = evm.view(CONSENSUS, IConsensusRegistry::committeeCall { epoch: 0 });
    assert_eq!(c.ids, (1..=n).collect::<Vec<_>>());
    let p = evm.view(CONSENSUS, IConsensusRegistry::phaseCall {});
    assert!(p.posScheduled);
    assert_eq!(p.posEpoch, 0);
    let keys = evm.view(STAKING, IStakingManager::keysOfCall { ids: vec![1, 2] });
    assert_eq!(&keys.pubkeys[..48], g.dev_validators[0].bls_pubkey.as_slice());
    assert_eq!(keys.recipients[1], g.dev_validators[1].fee_recipient);
    let staked: U256 = g.dev_validators.iter().map(|v| bolt(v.stake_bolt)).sum();
    assert_eq!(evm.view(STAKING, IStakingManager::totalActiveStakeCall {}), staked);
    assert_eq!(evm.balance(STAKING), staked);
    // Genesis stake counts as matured.
    assert_eq!(
        evm.view(STAKING, IStakingManager::maturedStakeCall { id: 1, minAge: 14 }),
        bolt(g.dev_validators[0].stake_bolt)
    );
    let funded: U256 = g.alloc.values().map(|a| a.balance).sum();
    assert_eq!(evm.view(REWARDS, IRewardDistributor::supplyCall {}), funded + staked);
    // Genesis-only functions are closed afterwards.
    assert!(!evm.try_call(
        SYSTEM,
        STAKING,
        U256::ZERO,
        IStakingManager::registerGenesisCall {
            pubkey: bytes(&[0; 48]),
            owner: Address::ZERO,
            feeRecipient: Address::ZERO,
            stake: U256::ZERO,
        }
    ));

    // Public genesis: nobody is a validator, the chain is mined, nothing is allocated.
    let g = Genesis::from_json(include_str!("../../../genesis/devnet.json")).unwrap();
    let mut evm = Evm::from_genesis(&g);
    let p = evm.view(CONSENSUS, IConsensusRegistry::phaseCall {});
    assert!(!p.posScheduled);
    assert!(evm.view(CONSENSUS, IConsensusRegistry::committeeCall { epoch: 0 }).ids.is_empty());
    assert_eq!(evm.view(STAKING, IStakingManager::countCall {}), 0);
    assert_eq!(evm.view(REWARDS, IRewardDistributor::supplyCall {}), U256::ZERO);
    // Only the system contracts (ComputeMarket and ModelRegistry, ADR 0011; the TEE contracts,
    // ADR 0013) and the two Osaka predeploys.
    let alloc = genesis_alloc(&g).unwrap();
    for a in [COMPUTE, MODELS, IMAGES, COLLATERAL, TDX, LEASES, WALLET] {
        assert!(alloc.contains_key(&a), "{a}");
    }
    assert_eq!(alloc.len(), 13, "{:?}", alloc.keys().collect::<Vec<_>>());
    assert!(alloc.values().all(|a| a.balance.is_zero()));
}

/// Registers validator `i` (dev key) from `owner` with `stake` wei.
pub(crate) fn register(evm: &mut Evm, i: u32, owner: Address, stake: U256) -> bool {
    let sk = dev_key(i);
    let pk = sk.public_key();
    evm.fund(owner, stake + U256::from(10u64).pow(U256::from(18)));
    evm.try_call(
        owner,
        STAKING,
        stake,
        IStakingManager::registerCall {
            pubkey: bytes(pk.as_slice()),
            pubkeyPoint: bytes(&pubkey_point(&pk).unwrap()),
            pop: bytes(&signature_point(&sk.proof_of_possession()).unwrap()),
            feeRecipient: owner,
        },
    )
}

fn bolt(n: u64) -> U256 {
    U256::from(n) * U256::from(10u64).pow(U256::from(18))
}

fn begin_epoch(evm: &mut Evm, epoch: u64) {
    evm.system(
        CONSENSUS,
        IConsensusRegistry::beginEpochCall {
            epoch,
            checkpointMet: false,
            posMet: false,
            streakRequired: 14,
        },
    );
}

#[test]
fn staking_register_exit_withdraw() {
    let mut evm = Evm::from_genesis(&dev_genesis());
    let alice = Address::repeat_byte(0xa1);
    // below the minimum
    assert!(!register(&mut evm, 20, alice, bolt(63)));
    assert!(register(&mut evm, 20, alice, bolt(64)));
    // same key twice
    assert!(!register(&mut evm, 20, Address::repeat_byte(0xa2), bolt(64)));
    // wrong proof of possession
    let (sk, other) = (dev_key(21), dev_key(22));
    evm.fund(alice, bolt(100));
    assert!(!evm.try_call(
        alice,
        STAKING,
        bolt(64),
        IStakingManager::registerCall {
            pubkey: bytes(sk.public_key().as_slice()),
            pubkeyPoint: bytes(&pubkey_point(&sk.public_key()).unwrap()),
            pop: bytes(&signature_point(&other.proof_of_possession()).unwrap()),
            feeRecipient: alice,
        }
    ));
    let id = evm.view(STAKING, IStakingManager::countCall {});
    assert_eq!(id, 8, "7 genesis validators + 1");
    let snap = evm.view(STAKING, IStakingManager::snapshotCall { minAge: 0 });
    assert_eq!(snap.ids.len(), 8);
    assert!(snap.ids.contains(&id));
    // Not matured yet: left out of a draw that requires 14 epochs of age.
    let snap = evm.view(STAKING, IStakingManager::snapshotCall { minAge: 14 });
    assert!(!snap.ids.contains(&id));
    begin_epoch(&mut evm, 13);
    assert_eq!(evm.view(STAKING, IStakingManager::maturedStakeCall { id, minAge: 14 }), U256::ZERO);
    begin_epoch(&mut evm, 14);
    assert_eq!(evm.view(STAKING, IStakingManager::maturedStakeCall { id, minAge: 14 }), bolt(64));
    // top-up by anyone (restarts the clock for the new deposit), exit by owner only
    evm.fund(Address::repeat_byte(0xb0), bolt(10));
    evm.call(Address::repeat_byte(0xb0), STAKING, bolt(1), IStakingManager::depositCall { id });
    assert_eq!(evm.view(STAKING, IStakingManager::maturedStakeCall { id, minAge: 14 }), bolt(64));
    assert_eq!(evm.view(STAKING, IStakingManager::maturedStakeCall { id, minAge: 0 }), bolt(65));
    assert!(!evm.try_call(
        Address::repeat_byte(0xb0),
        STAKING,
        U256::ZERO,
        IStakingManager::requestExitCall { id }
    ));
    evm.call(alice, STAKING, U256::ZERO, IStakingManager::requestExitCall { id });
    assert!(!evm.view(STAKING, IStakingManager::snapshotCall { minAge: 0 }).ids.contains(&id));
    // bonded for 1 + 14 epochs
    assert!(!evm.try_call(alice, STAKING, U256::ZERO, IStakingManager::withdrawCall { id }));
    begin_epoch(&mut evm, 28);
    assert!(!evm.try_call(alice, STAKING, U256::ZERO, IStakingManager::withdrawCall { id }));
    begin_epoch(&mut evm, 29);
    let before = evm.balance(alice);
    evm.call(alice, STAKING, U256::ZERO, IStakingManager::withdrawCall { id });
    assert_eq!(evm.balance(alice) - before, bolt(65));
}

/// Consensus message layouts (duplicated here so the contract test does not depend on the
/// consensus crate; the node-level test checks the real encoder).
fn vote_msg(chain: u64, epoch: u64, round: u64, block: B256) -> Vec<u8> {
    [
        b"boltchain/vote/v2".as_slice(),
        &chain.to_be_bytes(),
        &epoch.to_be_bytes(),
        &round.to_be_bytes(),
        block.as_slice(),
    ]
    .concat()
}

#[test]
fn double_vote_is_slashed() {
    let g = dev_genesis();
    let mut evm = Evm::from_genesis(&g);
    let owners: Vec<Address> = (0..10u8).map(|i| Address::repeat_byte(0x10 + i)).collect();
    for (i, o) in owners.iter().enumerate() {
        assert!(register(&mut evm, 30 + i as u32, *o, bolt(1000)));
    }
    let id = 8u32; // dev key 30
    let sk = dev_key(30);
    let (a, b) = (
        vote_msg(g.config.chain_id, 0, 5, B256::repeat_byte(1)),
        vote_msg(g.config.chain_id, 0, 5, B256::repeat_byte(2)),
    );
    let (sa, sb) = (sk.sign(&a), sk.sign(&b));
    let reporter = Address::repeat_byte(0xee);
    evm.fund(reporter, bolt(1));
    let data =
        crate::evidence::submit_evidence_calldata(id, &sk.public_key(), &a, &sa, &b, &sb).unwrap();
    // wrong validator id: rejected
    let wrong =
        crate::evidence::submit_evidence_calldata(id + 1, &sk.public_key(), &a, &sa, &b, &sb)
            .unwrap();
    assert!(!evm.tx(reporter, CONSENSUS, U256::ZERO, wrong.to_vec()).0);
    // same message twice: not a conflict
    let same =
        crate::evidence::submit_evidence_calldata(id, &sk.public_key(), &a, &sa, &a, &sa).unwrap();
    assert!(!evm.tx(reporter, CONSENSUS, U256::ZERO, same.to_vec()).0);
    // different rounds: not a conflict
    let c = vote_msg(g.config.chain_id, 0, 6, B256::repeat_byte(2));
    let other_round =
        crate::evidence::submit_evidence_calldata(id, &sk.public_key(), &a, &sa, &c, &sk.sign(&c))
            .unwrap();
    assert!(!evm.tx(reporter, CONSENSUS, U256::ZERO, other_round.to_vec()).0);
    // forged second signature
    let forged = crate::evidence::submit_evidence_calldata(
        id,
        &sk.public_key(),
        &a,
        &sa,
        &b,
        &dev_key(31).sign(&b),
    )
    .unwrap();
    assert!(!evm.tx(reporter, CONSENSUS, U256::ZERO, forged.to_vec()).0);

    let supply_before = evm.view(REWARDS, IRewardDistributor::supplyCall {});
    let bps = evm.view(CONSENSUS, IConsensusRegistry::slashBpsCall {});
    assert_eq!(bps, U256::from(500), "5% when nothing was slashed recently");
    let before = evm.balance(reporter);
    let (ok, out) = evm.tx(reporter, CONSENSUS, U256::ZERO, data.to_vec());
    assert!(ok, "{out}");
    let slashed = IConsensusRegistry::submitEvidenceCall::abi_decode_returns(&out).unwrap();
    assert_eq!(slashed, bolt(50));
    assert_eq!(evm.balance(reporter) - before, bolt(50) / U256::from(100));
    assert_eq!(
        supply_before - evm.view(REWARDS, IRewardDistributor::supplyCall {}),
        bolt(50) * U256::from(99) / U256::from(100)
    );
    let v = evm.view(STAKING, IStakingManager::validatorCall { id });
    assert_eq!(v.stake, bolt(950));
    assert!(matches!(v.status, IStakingManager::Status::Slashed));
    assert!(!evm.view(STAKING, IStakingManager::snapshotCall { minAge: 0 }).ids.contains(&id));
    // replay rejected
    assert!(!evm.tx(reporter, CONSENSUS, U256::ZERO, data.to_vec()).0);
    // correlated: the next offender pays more (5% + 3 x 50 / (9 x 1000 + 7 x 1000 genesis stake))
    let bps = evm.view(CONSENSUS, IConsensusRegistry::slashBpsCall {});
    assert_eq!(bps, U256::from(500 + 3 * 50 * 10_000 / 16_000));
}

#[test]
fn no_governance_only_the_node_can_call_admin_functions() {
    let g = dev_genesis();
    let mut evm = Evm::from_genesis(&g);
    let anyone = Address::repeat_byte(0x99);
    evm.fund(anyone, bolt(1));
    // Former governance addresses are empty; ParamRegistry's address stays unused.
    for a in [
        "0xB0170000000000000000000000000000000000A0",
        "0xB0170000000000000000000000000000000000A1",
        "0xB0170000000000000000000000000000000000A2",
        "0xB017000000000000000000000000000000000004",
    ] {
        let a: Address = a.parse().unwrap();
        assert!(evm.db.load_account(a).unwrap().info.code.as_ref().is_none_or(|c| c.is_empty()));
    }
    // No upgrade entry point.
    alloy_sol_types::sol! {
        function upgradeToAndCall(address newImplementation, bytes data) external payable;
    }
    for c in [STAKING, CONSENSUS, REWARDS, SWARM] {
        let call = upgradeToAndCallCall { newImplementation: anyone, data: Bytes::new() };
        assert!(!evm.try_call(anyone, c, U256::ZERO, call));
    }
    // System-only functions.
    assert!(!evm.try_call(
        anyone,
        CONSENSUS,
        U256::ZERO,
        IConsensusRegistry::beginEpochCall {
            epoch: 1,
            checkpointMet: true,
            posMet: true,
            streakRequired: 1
        }
    ));
    assert!(!evm.try_call(
        anyone,
        CONSENSUS,
        U256::ZERO,
        IConsensusRegistry::setCommitteeCall {
            epoch: 3,
            memberIds: vec![1],
            weights: vec![1],
            seats: bytes(&[0, 0]),
        }
    ));
    assert!(!evm.try_call(
        anyone,
        REWARDS,
        U256::ZERO,
        IRewardDistributor::onBlockCall {
            burned: U256::ZERO,
            minted: bolt(1_000_000),
            certEpoch: 0,
            certRound: 0,
            bitmap: Bytes::new(),
        }
    ));
    assert!(!evm.try_call(
        anyone,
        REWARDS,
        U256::ZERO,
        IRewardDistributor::settleCall { epoch: 0, emission: bolt(1) }
    ));
}

#[test]
fn phases_are_scheduled_after_the_threshold_streaks() {
    let g = Genesis::from_json(include_str!("../../../genesis/devnet.json")).unwrap();
    let mut evm = Evm::from_genesis(&g);
    let begin = |evm: &mut Evm, epoch: u64, t1: bool, t2: bool| {
        evm.system(
            CONSENSUS,
            IConsensusRegistry::beginEpochCall {
                epoch,
                checkpointMet: t1,
                posMet: t2,
                streakRequired: 3,
            },
        )
    };
    assert!(!begin(&mut evm, 1, true, false).cpScheduled);
    assert!(!begin(&mut evm, 2, true, false).cpScheduled);
    // A miss restarts the count.
    assert!(!begin(&mut evm, 3, false, false).cpScheduled);
    assert_eq!(evm.view(CONSENSUS, IConsensusRegistry::phaseCall {}).checkpointStreak, 0);
    assert!(!begin(&mut evm, 4, true, false).cpScheduled);
    assert!(!begin(&mut evm, 5, true, true).cpScheduled);
    let r = begin(&mut evm, 6, true, true);
    assert!(r.cpScheduled && !r.scheduled);
    assert_eq!(r.firstCheckpointEpoch, 8, "phase B two epochs later");
    assert!(!begin(&mut evm, 7, true, false).scheduled);
    let r = begin(&mut evm, 8, true, false);
    assert!(!r.scheduled, "T2 streak broken");
    for e in 9..11 {
        assert!(!begin(&mut evm, e, true, true).scheduled);
    }
    let r = begin(&mut evm, 11, true, true);
    assert!(r.scheduled);
    assert_eq!(r.firstPosEpoch, 13);
    assert_eq!(r.firstCheckpointEpoch, 8, "unchanged");
    // Final: later misses change nothing.
    let r = begin(&mut evm, 12, false, false);
    assert!(r.scheduled && r.cpScheduled);

    // Stake that jumps straight past T2 skips phase B.
    let mut evm = Evm::from_genesis(&g);
    for e in 1..3 {
        begin(&mut evm, e, true, true);
    }
    let r = begin(&mut evm, 3, true, true);
    assert_eq!((r.firstCheckpointEpoch, r.firstPosEpoch), (5, 5));

    // Mined blocks add their reward to the supply; a certificate's votes count once.
    evm.system(
        REWARDS,
        IRewardDistributor::onBlockCall {
            burned: U256::ZERO,
            minted: bolt(5),
            certEpoch: 4,
            certRound: 7,
            bitmap: bytes(&[0b11]),
        },
    );
    assert_eq!(evm.view(REWARDS, IRewardDistributor::supplyCall {}), bolt(5));
    for round in [7, 6, 8] {
        evm.system(
            REWARDS,
            IRewardDistributor::onBlockCall {
                burned: U256::ZERO,
                minted: U256::ZERO,
                certEpoch: 4,
                certRound: round,
                bitmap: bytes(&[0b01]),
            },
        );
    }
    let votes = |evm: &mut Evm, i| {
        evm.view(REWARDS, IRewardDistributor::votesOfCall { epoch: 4, index: U256::from(i) })
    };
    assert_eq!(votes(&mut evm, 0), U256::from(2), "rounds 7 and 8; the repeat and 6 are ignored");
    assert_eq!(votes(&mut evm, 1), U256::from(1));
}

/// Genesis now includes the compiled system contracts: any change to them, to the deployment
/// procedure or to genesis construction changes this hash. Update it deliberately (and note the
/// new devnet hash in the milestone log).
#[test]
fn devnet_genesis_hash_is_pinned() {
    let g = Genesis::from_json(include_str!("../../../genesis/devnet.json")).unwrap();
    assert_eq!(
        crate::genesis_hash(&g).unwrap(),
        "0xdd0c76a261ea871c3134fd81159bb069cc2abb31ff37c2538daa5173dd05e44b"
            .parse::<B256>()
            .unwrap()
    );
    // The public testnet (restarted with ADR 0012's rules): every chain has ComputeMarket at
    // genesis.
    let t = Genesis::from_json(include_str!("../../../genesis/testnet.json")).unwrap();
    assert_eq!(
        crate::genesis_hash(&t).unwrap(),
        "0x0dd221dfcc1a212819e50717e4700e464cd0bf61065df9ed1c624c426ce162bb"
            .parse::<B256>()
            .unwrap()
    );
    assert!(genesis_alloc(&t).unwrap().contains_key(&COMPUTE));
    // Deterministic across runs (no dependence on the cache).
    assert_eq!(
        crate::genesis::genesis_state_root(&g).unwrap(),
        crate::genesis::genesis_state_root(&g).unwrap()
    );
}

#[test]
fn gas_of_registration_and_evidence() {
    let g = dev_genesis();
    let mut evm = Evm::from_genesis(&g);
    let owner = Address::repeat_byte(0x31);
    let sk = dev_key(40);
    let pk = sk.public_key();
    evm.fund(owner, bolt(100));
    let (ok, _, reg) = evm.tx_gas(
        owner,
        STAKING,
        bolt(64),
        IStakingManager::registerCall {
            pubkey: bytes(pk.as_slice()),
            pubkeyPoint: bytes(&pubkey_point(&pk).unwrap()),
            pop: bytes(&signature_point(&sk.proof_of_possession()).unwrap()),
            feeRecipient: owner,
        }
        .abi_encode(),
    );
    assert!(ok);
    let (a, b) = (
        vote_msg(g.config.chain_id, 0, 1, B256::repeat_byte(1)),
        vote_msg(g.config.chain_id, 0, 1, B256::repeat_byte(2)),
    );
    let data =
        crate::evidence::submit_evidence_calldata(8, &pk, &a, &sk.sign(&a), &b, &sk.sign(&b))
            .unwrap();
    let (ok, _, ev) = evm.tx_gas(owner, CONSENSUS, U256::ZERO, data.to_vec());
    assert!(ok);
    eprintln!("gas: register {reg}, submitEvidence {ev}");
    assert!(reg < 600_000 && ev < 900_000, "register {reg}, evidence {ev}");
}
