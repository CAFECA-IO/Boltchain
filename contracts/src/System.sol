// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title Fixed addresses and protocol constants shared by the Boltchain system contracts.
/// @notice There is no governance (ADR 0008): the contracts are deployed at genesis, cannot be
/// upgraded or paused, and change only through a hard fork of the node software.
library Sys {
    /// Caller of node-issued system calls (as EIP-4788 / EIP-2935).
    address internal constant SYSTEM = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;

    address internal constant STAKING = 0xB017000000000000000000000000000000000001;
    address internal constant CONSENSUS = 0xB017000000000000000000000000000000000002;
    address internal constant REWARDS = 0xb017000000000000000000000000000000000003;
    // 0xb017…0004 was ParamRegistry; left unused.
    /// SwarmStorage (was SwarmStorage; ADR 0014).
    address internal constant HISTORY = 0xb017000000000000000000000000000000000005;
    address internal constant COMPUTE = 0xB017000000000000000000000000000000000006;
    /// ModelRegistry (ADR 0011 §7).
    address internal constant MODELS = 0xb017000000000000000000000000000000000007;
    /// ImageRegistry, TeeCollateral, TdxVerifier, EnclaveLease, LimitedWallet (ADR 0013).
    address internal constant IMAGES = 0xB017000000000000000000000000000000000008;
    address internal constant COLLATERAL = 0xB017000000000000000000000000000000000009;
    address internal constant TDX = 0xB01700000000000000000000000000000000000a;
    address internal constant LEASES = 0xB01700000000000000000000000000000000000B;
    address internal constant WALLET = 0xB01700000000000000000000000000000000000C;

    uint256 internal constant MIN_STAKE = 64 ether;
    /// Unbonding period, in epochs (14 days); also the evidence window.
    uint64 internal constant UNBONDING_EPOCHS = 14;
}

/// @title Base for system contracts: calls reserved to the node (system address).
abstract contract SystemContract {
    error Unauthorized();

    modifier onlySystem() {
        if (msg.sender != Sys.SYSTEM) revert Unauthorized();
        _;
    }

    /// Genesis-only initialisation, executed by the node as the system address at block 0.
    modifier onlyGenesis() {
        if (msg.sender != Sys.SYSTEM || block.number != 0) revert Unauthorized();
        _;
    }
}
