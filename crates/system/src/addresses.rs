//! Fixed addresses of the system contracts (must match `contracts/src/System.sol`).

use alloy_primitives::{Address, address};

/// Caller of system calls (as EIP-4788 / EIP-2935).
pub const SYSTEM: Address = address!("0xfffffffffffffffffffffffffffffffffffffffe");

/// StakingManager.
pub const STAKING: Address = address!("0xB017000000000000000000000000000000000001");
/// ConsensusRegistry.
pub const CONSENSUS: Address = address!("0xB017000000000000000000000000000000000002");
/// RewardDistributor.
pub const REWARDS: Address = address!("0xB017000000000000000000000000000000000003");
/// SwarmStorage (M5).
pub const SWARM: Address = address!("0xB017000000000000000000000000000000000005");
/// ComputeMarket (ADR 0011).
pub const COMPUTE: Address = address!("0xB017000000000000000000000000000000000006");
/// ModelRegistry (ADR 0011 §7).
pub const MODELS: Address = address!("0xB017000000000000000000000000000000000007");
/// ImageRegistry (ADR 0013).
pub const IMAGES: Address = address!("0xB017000000000000000000000000000000000008");
/// TeeCollateral (ADR 0013).
pub const COLLATERAL: Address = address!("0xB017000000000000000000000000000000000009");
/// TdxVerifier (ADR 0013).
pub const TDX: Address = address!("0xB01700000000000000000000000000000000000a");
/// EnclaveLease (ADR 0013).
pub const LEASES: Address = address!("0xB01700000000000000000000000000000000000B");
/// LimitedWallet, the EIP-7702 delegation target for agent accounts (ADR 0013 §7).
pub const WALLET: Address = address!("0xB01700000000000000000000000000000000000C");
