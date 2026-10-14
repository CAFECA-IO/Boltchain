// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Sys} from "./System.sol";

interface ILeaseSigner {
    function activeSigner(uint256 id) external view returns (address);
}

/// @title Limited wallet for agents (ADR 0013 §7): an EIP-7702 delegate.
/// @notice An account delegates to this code (`authorization` to Sys.WALLET) and configures,
/// by calling itself, a lease and limits. The lease's active enclave key then acts as a session
/// key: it may send calls to whitelisted targets, each at most `perTxLimit` in value and in all
/// at most `dailyLimit` per UTC day, directly or as a signed meta-transaction anyone submits.
/// When the lease moves to a new enclave the old key stops working, since the key is read from
/// `EnclaveLease` on every call. The owner keeps full control (its own transactions are not
/// limited) and can revoke at any time. Storage is namespaced so it does not collide with other
/// code the account may delegate to later.
contract LimitedWallet {
    /// keccak256("boltchain.limited-wallet.v1") - 1
    bytes32 internal constant SLOT = 0x09d79b1c56cf8a94ff3e68a29cbe0e8216fc618d951fb1c06e33cdca68340d95;

    struct Config {
        uint256 lease;
        uint128 dailyLimit;
        uint128 perTxLimit;
        uint64 day;
        uint128 spentToday;
        uint64 nonce;
        mapping(address => bool) allowed;
        address[] targets;
    }

    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    event Configured(uint256 lease, uint128 dailyLimit, uint128 perTxLimit, address[] targets);
    event Revoked();
    event Executed(address indexed by, address indexed to, uint256 value);

    error NotAllowed();
    error OverLimit();
    error BadSignature();
    error Expired();
    error CallFailed(bytes reason);

    function _cfg() internal pure returns (Config storage c) {
        bytes32 slot = SLOT;
        assembly {
            c.slot := slot
        }
    }

    /// The account (calling itself) sets the lease whose enclave may act and its limits.
    function configure(uint256 lease, uint128 dailyLimit, uint128 perTxLimit, address[] calldata targets) external {
        if (msg.sender != address(this)) revert NotAllowed();
        Config storage c = _cfg();
        for (uint256 i = 0; i < c.targets.length; i++) {
            c.allowed[c.targets[i]] = false;
        }
        delete c.targets;
        for (uint256 i = 0; i < targets.length; i++) {
            c.allowed[targets[i]] = true;
            c.targets.push(targets[i]);
        }
        c.lease = lease;
        c.dailyLimit = dailyLimit;
        c.perTxLimit = perTxLimit;
        emit Configured(lease, dailyLimit, perTxLimit, targets);
    }

    /// The account (calling itself) stops the session key.
    function revoke() external {
        if (msg.sender != address(this)) revert NotAllowed();
        _cfg().lease = 0;
        emit Revoked();
    }

    /// Runs `calls`: unlimited for the account itself, within the limits for the lease's active
    /// enclave key.
    function execute(Call[] calldata calls) external payable {
        if (msg.sender != address(this)) _check(msg.sender, calls);
        _run(calls);
    }

    /// Digest the enclave key signs (EIP-191) for `executeSigned`.
    function executeDigest(Call[] calldata calls, uint64 nonce, uint256 deadline) public view returns (bytes32) {
        bytes32 h = keccak256(abi.encode(keccak256("boltchain/wallet/v1"), block.chainid, address(this), calls, nonce, deadline));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    /// Runs `calls` signed by the lease's active enclave key; anyone may submit (the enclave
    /// needs no gas of its own).
    function executeSigned(Call[] calldata calls, uint256 deadline, bytes calldata sig) external {
        if (block.timestamp > deadline) revert Expired();
        Config storage c = _cfg();
        address signer = _recover(executeDigest(calls, c.nonce, deadline), sig);
        if (signer == address(0)) revert BadSignature();
        c.nonce++;
        _check(signer, calls);
        _run(calls);
    }

    function _check(address by, Call[] calldata calls) internal {
        Config storage c = _cfg();
        if (c.lease == 0 || by != ILeaseSigner(Sys.LEASES).activeSigner(c.lease)) revert NotAllowed();
        uint64 today = uint64(block.timestamp / 1 days);
        if (c.day != today) {
            c.day = today;
            c.spentToday = 0;
        }
        uint256 total;
        for (uint256 i = 0; i < calls.length; i++) {
            if (!c.allowed[calls[i].to]) revert NotAllowed();
            if (calls[i].value > c.perTxLimit) revert OverLimit();
            total += calls[i].value;
        }
        if (c.spentToday + total > c.dailyLimit) revert OverLimit();
        c.spentToday += uint128(total);
    }

    function _run(Call[] calldata calls) internal {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(ret);
            emit Executed(msg.sender, calls[i].to, calls[i].value);
        }
    }

    function config()
        external
        view
        returns (uint256 lease, uint128 dailyLimit, uint128 perTxLimit, uint128 spentToday, uint64 nonce, address[] memory targets)
    {
        Config storage c = _cfg();
        uint128 spent = c.day == uint64(block.timestamp / 1 days) ? c.spentToday : 0;
        return (c.lease, c.dailyLimit, c.perTxLimit, spent, c.nonce, c.targets);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) return address(0);
        return ecrecover(digest, v, r, s);
    }

    receive() external payable {}
}
