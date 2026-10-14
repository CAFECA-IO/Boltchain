// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Sys, SystemContract} from "./System.sol";

/// @title AI compute market (ADR 0011).
/// @notice Requesters escrow BOLT for AI inference priced per 1,000 input and output tokens;
/// providers run it and are paid on settlement. Inputs and outputs are bolt-vault files on IPFS
/// (only their CIDs appear here). Providers need no BOLT to start: every provider action can be
/// signed off-chain and submitted by anyone (the requester or a relayer), a relayer's
/// registration fee is repaid from the provider's first earnings, and the provider's bond is
/// withheld from its earnings instead of being paid up front.
///
/// Settlement is optimistic: a delivered job is paid when the requester approves it or its
/// dispute window passes. A requester may dispute within the window (with a deposit); the node
/// assigns disputes to a verifier panel drawn from the committee, the requester discloses the
/// files to the panel (bolt-vault recipients), and the panel's certified verdict is recorded by a
/// system call.
///
/// There is no emission here (ADR 0012): providers earn only what requesters pay.
contract ComputeMarket is SystemContract {
    // ------------------------------------------------------------------ constants

    /// Bond each provider accumulates from its earnings.
    uint256 public constant BOND_TARGET = 64 ether;
    /// Share of each payout withheld until the bond reaches the target.
    uint256 public constant BOND_BPS = 2_000;
    /// Largest job a provider without bond may take; grows by BOND_MULTIPLE x bond.
    uint256 public constant BASE_JOB_LIMIT = 5 ether;
    uint256 public constant BOND_MULTIPLE = 10;
    /// Largest fee a relayer may charge for registering a provider.
    uint256 public constant MAX_REGISTRATION_FEE = 1 ether;
    /// Largest fee a relayer may charge for submitting a provider's signed acceptance or receipt.
    uint256 public constant MAX_RELAY_FEE = 0.1 ether;
    /// Deposit to open a dispute (returned if the panel finds the provider at fault).
    uint256 public constant DISPUTE_DEPOSIT = 1 ether;
    /// Share of the bond a provider loses when a panel finds it at fault.
    uint256 public constant FAULT_SLASH_BPS = 1_000;
    /// Dispute window bounds, in seconds.
    uint64 public constant MIN_WINDOW = 10 minutes;
    uint64 public constant MAX_WINDOW = 7 days;
    /// A dispute without a verdict after this long settles in the provider's favour.
    uint64 public constant VERDICT_TIMEOUT = 7 days;
    /// Epochs a leaving provider waits before withdrawing its bond.
    uint64 public constant EXIT_EPOCHS = Sys.UNBONDING_EPOCHS;

    // ------------------------------------------------------------------ providers

    struct Provider {
        bool registered;
        bytes peerId; // libp2p peer id of the provider's node
        uint256 bond;
        uint256 debt; // owed to `debtTo` (registration relayer), repaid from earnings
        address debtTo;
        uint32 jobsDone;
        uint32 faults;
        uint64 exitEpoch; // 0 = active
    }

    mapping(address => Provider) internal providers;
    /// X25519 public key for bolt-vault files, per account (providers, requesters, verifiers).
    mapping(address => bytes32) public encryptionKey;
    /// Withdrawable balance per account.
    mapping(address => uint256) public balanceOf;
    /// Nonce per account for signed actions.
    mapping(address => uint256) public nonces;

    // ------------------------------------------------------------------ jobs

    enum JobState {
        None,
        Open,
        Accepted,
        Delivered,
        Disputed,
        Settled,
        Refunded
    }

    struct Job {
        address requester;
        address provider; // required provider, or 0 for any
        JobState state;
        uint64 model; // ModelRegistry id (off-chain registry until then)
        uint64 deadline; // delivery deadline (timestamp)
        uint64 window; // dispute window after delivery (seconds)
        uint64 deliveredAt;
        uint64 tokensIn;
        uint64 tokensOut;
        uint64 maxIn;
        uint64 maxOut;
        uint128 priceIn; // wei per 1,000 input tokens
        uint128 priceOut; // wei per 1,000 output tokens
        uint128 relayFee; // paid to whoever settles the job (0 if the requester does)
        uint128 escrow;
        bytes input; // bolt-vault envelope CID of the input
        bytes output; // bolt-vault envelope CID of the output
    }

    Job[] internal jobs;

    /// Relayers that submitted a provider's signed acceptance and receipt, and their fees. Paid
    /// out of the job's cost (before the provider's share) when the job settles; nothing if it
    /// does not (a relayer takes the provider's risk). Kept apart from `Job` so jobs stored by
    /// earlier versions keep their layout.
    struct Relay {
        address acceptRelayer;
        uint128 acceptFee;
        address deliverRelayer;
        uint128 deliverFee;
    }

    mapping(uint256 => Relay) public relays;

    // ------------------------------------------------------------------ disputes and panels

    struct Dispute {
        uint64 openedAt;
        uint64 panelEpoch; // epoch whose panel decides (0 until assigned)
        bytes reason; // bolt-vault envelope CID of the requester's statement
    }

    mapping(uint256 => Dispute) public disputes;
    /// Disputes waiting for a panel.
    uint256[] internal unassigned;
    /// Verifier panel (validator ids) per epoch.
    mapping(uint64 => uint32[]) internal panels;

    // ------------------------------------------------------------------ events and errors

    event ProviderRegistered(address indexed provider, bytes peerId, address relayer, uint256 fee);
    event EncryptionKeySet(address indexed account, bytes32 key);
    event JobPosted(uint256 indexed id, address indexed requester, address provider, uint64 model, bytes input);
    event InputShared(uint256 indexed id, bytes input);
    event JobAccepted(uint256 indexed id, address indexed provider);
    event JobDelivered(uint256 indexed id, bytes output, uint64 tokensIn, uint64 tokensOut);
    event JobSettled(uint256 indexed id, uint256 toProvider, uint256 bond, uint256 refund, uint256 relayFee);
    event JobRefunded(uint256 indexed id, uint256 amount);
    event Disputed(uint256 indexed id, bytes reason);
    event PanelAssigned(uint64 indexed epoch, uint256 disputes);
    event Verdict(uint256 indexed id, bool providerAtFault, uint256 slashed);
    event Withdrawn(address indexed account, address to, uint256 amount);
    event ExitRequested(address indexed provider, uint64 epoch);

    error BadSignature();
    error Expired();
    error NotRegistered();
    error AlreadyRegistered();
    error FeeTooHigh();
    error BadState();
    error BadParams();
    error NotAllowed();
    error OverLimit();
    error TransferFailed();
    error Exiting();
    error UnknownModel();

    // ------------------------------------------------------------------ signatures

    /// EIP-191 personal-sign hash of an action (bound to this chain, contract and the signer's
    /// nonce).
    function _digest(bytes32 action, address signer, bytes memory data) internal view returns (bytes32) {
        bytes32 h = keccak256(abi.encode(block.chainid, address(this), action, signer, nonces[signer], data));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function _verify(bytes32 action, address signer, bytes memory data, uint256 deadline, bytes calldata sig)
        internal
    {
        if (block.timestamp > deadline) revert Expired();
        if (sig.length != 65) revert BadSignature();
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        // Reject malleable signatures (EIP-2).
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert BadSignature();
        address got = ecrecover(_digest(action, signer, abi.encode(data, deadline)), v, r, s);
        if (got == address(0) || got != signer) revert BadSignature();
        nonces[signer]++;
    }

    /// Digest a provider signs for a signed action (for wallets and tests).
    function actionDigest(bytes32 action, address signer, bytes calldata data, uint256 deadline)
        external
        view
        returns (bytes32)
    {
        return _digest(action, signer, abi.encode(data, deadline));
    }

    // ------------------------------------------------------------------ providers

    function _register(address p, bytes32 encKey, bytes memory peerId, address relayer, uint256 fee) internal {
        Provider storage pr = providers[p];
        if (pr.registered) revert AlreadyRegistered();
        if (fee > MAX_REGISTRATION_FEE) revert FeeTooHigh();
        pr.registered = true;
        pr.peerId = peerId;
        if (fee != 0) {
            pr.debt = fee;
            pr.debtTo = relayer;
        }
        encryptionKey[p] = encKey;
        emit ProviderRegistered(p, peerId, relayer, fee);
        emit EncryptionKeySet(p, encKey);
    }

    /// Registers the caller as a provider (costs gas; see `registerFor` for BOLT-less providers).
    function register(bytes32 encKey, bytes calldata peerId) external {
        _register(msg.sender, encKey, peerId, address(0), 0);
    }

    /// Registers `provider` from its signature; the caller (relayer) is repaid `fee` from the
    /// provider's first earnings.
    function registerFor(
        address provider_,
        bytes32 encKey,
        bytes calldata peerId,
        uint256 fee,
        uint256 deadline,
        bytes calldata sig
    ) external {
        _verify("register", provider_, abi.encode(encKey, peerId, fee), deadline, sig);
        _register(provider_, encKey, peerId, msg.sender, fee);
    }

    /// Sets the caller's bolt-vault encryption key.
    function setEncryptionKey(bytes32 key) external {
        encryptionKey[msg.sender] = key;
        emit EncryptionKeySet(msg.sender, key);
    }

    /// Stops taking jobs; the bond can be withdrawn after EXIT_EPOCHS.
    function requestExit() external {
        Provider storage pr = providers[msg.sender];
        if (!pr.registered || pr.exitEpoch != 0) revert BadState();
        pr.exitEpoch = _epoch() + EXIT_EPOCHS;
        emit ExitRequested(msg.sender, pr.exitEpoch);
    }

    /// Withdraws the bond after the exit delay (into the withdrawable balance).
    function releaseBond() external {
        Provider storage pr = providers[msg.sender];
        if (pr.exitEpoch == 0 || _epoch() < pr.exitEpoch) revert BadState();
        balanceOf[msg.sender] += pr.bond;
        pr.bond = 0;
    }

    function provider(address p)
        external
        view
        returns (bool registered, bytes memory peerId, uint256 bond, uint256 debt, uint32 jobsDone, uint32 faults, uint64 exitEpoch)
    {
        Provider storage pr = providers[p];
        return (pr.registered, pr.peerId, pr.bond, pr.debt, pr.jobsDone, pr.faults, pr.exitEpoch);
    }

    /// Largest escrow a provider may take on.
    function jobLimit(address p) public view returns (uint256) {
        return BASE_JOB_LIMIT + BOND_MULTIPLE * providers[p].bond;
    }

    /// Credits a provider's earnings: repays its registration debt, then withholds BOND_BPS until
    /// the bond reaches BOND_TARGET. Returns (paid to the provider, added to the bond).
    function _earn(address p, uint256 amount) internal returns (uint256 paid, uint256 toBond) {
        Provider storage pr = providers[p];
        if (pr.debt != 0) {
            uint256 d = amount < pr.debt ? amount : pr.debt;
            pr.debt -= d;
            balanceOf[pr.debtTo] += d;
            amount -= d;
        }
        if (pr.bond < BOND_TARGET) {
            toBond = amount * BOND_BPS / 10_000;
            if (pr.bond + toBond > BOND_TARGET) toBond = BOND_TARGET - pr.bond;
            pr.bond += toBond;
        }
        paid = amount - toBond;
        balanceOf[p] += paid;
    }

    // ------------------------------------------------------------------ jobs

    /// Posts a job and escrows its maximum cost plus the relay fee. `provider` = 0 lets any
    /// registered provider accept it.
    function post(
        address provider_,
        uint64 model,
        bytes calldata input,
        uint128 priceIn,
        uint128 priceOut,
        uint64 maxIn,
        uint64 maxOut,
        uint64 deadline,
        uint64 window,
        uint128 relayFee
    ) external payable returns (uint256 id) {
        if (window < MIN_WINDOW || window > MAX_WINDOW || deadline <= block.timestamp) revert BadParams();
        if (!_modelExists(model)) revert UnknownModel();
        uint256 maxCost = _cost(maxIn, priceIn) + _cost(maxOut, priceOut);
        if (msg.value < maxCost + relayFee || msg.value > type(uint128).max) revert BadParams();
        id = jobs.length;
        jobs.push(
            Job({
                requester: msg.sender,
                provider: provider_,
                state: JobState.Open,
                model: model,
                deadline: deadline,
                window: window,
                deliveredAt: 0,
                tokensIn: 0,
                tokensOut: 0,
                maxIn: maxIn,
                maxOut: maxOut,
                priceIn: priceIn,
                priceOut: priceOut,
                relayFee: relayFee,
                escrow: uint128(msg.value),
                input: input,
                output: ""
            })
        );
        emit JobPosted(id, msg.sender, provider_, model, input);
    }

    function _cost(uint64 tokens, uint128 pricePerK) internal pure returns (uint256) {
        return uint256(tokens) * pricePerK / 1000;
    }

    function _accept(uint256 id, address p) internal {
        Job storage j = jobs[id];
        Provider storage pr = providers[p];
        if (j.state != JobState.Open || block.timestamp > j.deadline) revert BadState();
        if (!pr.registered) revert NotRegistered();
        if (pr.exitEpoch != 0) revert Exiting();
        if (j.provider != address(0) && j.provider != p) revert NotAllowed();
        if (j.escrow > jobLimit(p)) revert OverLimit();
        j.provider = p;
        j.state = JobState.Accepted;
        emit JobAccepted(id, p);
    }

    /// The caller (a registered provider) takes the job.
    function accept(uint256 id) external {
        _accept(id, msg.sender);
    }

    /// Takes the job for `provider` from its signature, submitted by anyone (the requester, or a
    /// relayer for a provider without BOLT). The provider agrees to `fee` for the caller, paid
    /// from the job's cost when it settles.
    function acceptFor(uint256 id, address provider_, uint128 fee, uint256 deadline, bytes calldata sig) external {
        if (fee > MAX_RELAY_FEE) revert FeeTooHigh();
        _verify("accept", provider_, abi.encode(id, fee), deadline, sig);
        _accept(id, provider_);
        if (fee != 0) {
            relays[id].acceptRelayer = msg.sender;
            relays[id].acceptFee = fee;
        }
    }

    /// The requester publishes the input envelope that includes the provider as a recipient
    /// (bolt-vault `add_recipient`, no re-upload).
    function shareInput(uint256 id, bytes calldata input) external {
        Job storage j = jobs[id];
        if (msg.sender != j.requester || j.state != JobState.Accepted) revert NotAllowed();
        j.input = input;
        emit InputShared(id, input);
    }

    function _deliver(uint256 id, address p, bytes memory output, uint64 tokensIn, uint64 tokensOut) internal {
        Job storage j = jobs[id];
        if (j.state != JobState.Accepted || j.provider != p) revert BadState();
        if (block.timestamp > j.deadline) revert Expired();
        if (tokensIn > j.maxIn || tokensOut > j.maxOut) revert BadParams();
        j.output = output;
        j.tokensIn = tokensIn;
        j.tokensOut = tokensOut;
        j.deliveredAt = uint64(block.timestamp);
        j.state = JobState.Delivered;
        emit JobDelivered(id, output, tokensIn, tokensOut);
    }

    /// The provider's receipt: output envelope CID and the tokens consumed.
    function deliver(uint256 id, bytes calldata output, uint64 tokensIn, uint64 tokensOut) external {
        _deliver(id, msg.sender, output, tokensIn, tokensOut);
    }

    /// The provider's signed receipt, submitted by anyone.
    function deliverFor(
        uint256 id,
        address provider_,
        bytes calldata output,
        uint64 tokensIn,
        uint64 tokensOut,
        uint128 fee,
        uint256 deadline,
        bytes calldata sig
    ) external {
        if (fee > MAX_RELAY_FEE) revert FeeTooHigh();
        _verify("deliver", provider_, abi.encode(id, output, tokensIn, tokensOut, fee), deadline, sig);
        _deliver(id, provider_, output, tokensIn, tokensOut);
        if (fee != 0) {
            relays[id].deliverRelayer = msg.sender;
            relays[id].deliverFee = fee;
        }
    }

    /// Pays a delivered job: when the requester approves it, or by anyone once the dispute window
    /// passed (the caller then earns the relay fee).
    function settle(uint256 id) external {
        Job storage j = jobs[id];
        if (j.state != JobState.Delivered) revert BadState();
        bool byRequester = msg.sender == j.requester;
        if (!byRequester && block.timestamp < j.deliveredAt + j.window) revert NotAllowed();
        _pay(id, byRequester ? j.requester : msg.sender);
    }

    function _pay(uint256 id, address relayer) internal {
        Job storage j = jobs[id];
        j.state = JobState.Settled;
        uint256 cost = _cost(j.tokensIn, j.priceIn) + _cost(j.tokensOut, j.priceOut);
        uint256 fee = relayer == j.requester ? 0 : j.relayFee;
        uint256 back = j.escrow - cost - fee;
        // Relayers of the provider's signed acceptance and receipt first, out of the cost.
        uint256 earned = cost;
        Relay storage r = relays[id];
        if (r.acceptFee != 0) {
            uint256 f = r.acceptFee < earned ? r.acceptFee : earned;
            balanceOf[r.acceptRelayer] += f;
            earned -= f;
        }
        if (r.deliverFee != 0) {
            uint256 f = r.deliverFee < earned ? r.deliverFee : earned;
            balanceOf[r.deliverRelayer] += f;
            earned -= f;
        }
        (uint256 paid, uint256 toBond) = _earn(j.provider, earned);
        providers[j.provider].jobsDone++;
        if (fee != 0) balanceOf[relayer] += fee;
        if (back != 0) balanceOf[j.requester] += back;
        emit JobSettled(id, paid, toBond, back, fee);
    }

    /// Returns the escrow of a job nobody accepted, or that was not delivered by its deadline
    /// (the provider's fault count grows).
    function refund(uint256 id) external {
        Job storage j = jobs[id];
        bool open = j.state == JobState.Open && (msg.sender == j.requester || block.timestamp > j.deadline);
        bool late = j.state == JobState.Accepted && block.timestamp > j.deadline;
        if (!open && !late) revert BadState();
        if (late) providers[j.provider].faults++;
        j.state = JobState.Refunded;
        balanceOf[j.requester] += j.escrow;
        emit JobRefunded(id, j.escrow);
    }

    /// The requester disputes a delivery within its window (with DISPUTE_DEPOSIT); `reason` is a
    /// bolt-vault envelope the panel will be able to read.
    function dispute(uint256 id, bytes calldata reason) external payable {
        Job storage j = jobs[id];
        if (msg.sender != j.requester || j.state != JobState.Delivered) revert NotAllowed();
        if (block.timestamp >= j.deliveredAt + j.window) revert Expired();
        if (msg.value != DISPUTE_DEPOSIT) revert BadParams();
        j.state = JobState.Disputed;
        disputes[id] = Dispute({openedAt: uint64(block.timestamp), panelEpoch: 0, reason: reason});
        unassigned.push(id);
        emit Disputed(id, reason);
    }

    /// First block of `epoch`: the node assigns waiting disputes to this epoch's verifier panel.
    function assignDisputes(uint64 epoch, uint32[] calldata members) external onlySystem {
        uint256 n = unassigned.length;
        if (n == 0) return;
        panels[epoch] = members;
        for (uint256 i = 0; i < n; i++) {
            disputes[unassigned[i]].panelEpoch = epoch;
        }
        delete unassigned;
        emit PanelAssigned(epoch, n);
    }

    /// The panel's certified verdict (checked by the node against the panel's keys). At fault:
    /// the requester gets the escrow and its deposit back plus the slashed bond; otherwise the
    /// job is paid and the deposit goes to the provider.
    function recordVerdict(uint256 id, bool providerAtFault) external onlySystem returns (bool) {
        Job storage j = jobs[id];
        if (j.state != JobState.Disputed || disputes[id].panelEpoch == 0) return false;
        uint256 slashed;
        if (providerAtFault) {
            Provider storage pr = providers[j.provider];
            slashed = pr.bond * FAULT_SLASH_BPS / 10_000;
            pr.bond -= slashed;
            pr.faults++;
            j.state = JobState.Refunded;
            balanceOf[j.requester] += j.escrow + DISPUTE_DEPOSIT + slashed;
        } else {
            _pay(id, j.requester);
            balanceOf[j.provider] += DISPUTE_DEPOSIT;
        }
        emit Verdict(id, providerAtFault, slashed);
        return true;
    }

    /// A dispute left without verdict for VERDICT_TIMEOUT settles for the provider; the requester
    /// gets its deposit back.
    function expireDispute(uint256 id) external {
        Job storage j = jobs[id];
        if (j.state != JobState.Disputed || block.timestamp < disputes[id].openedAt + VERDICT_TIMEOUT) {
            revert BadState();
        }
        _pay(id, j.requester);
        balanceOf[j.requester] += DISPUTE_DEPOSIT;
    }

    function job(uint256 id) external view returns (Job memory) {
        return jobs[id];
    }

    function jobCount() external view returns (uint256) {
        return jobs.length;
    }

    function panel(uint64 epoch) external view returns (uint32[] memory) {
        return panels[epoch];
    }

    function pendingDisputes() external view returns (uint256[] memory) {
        return unassigned;
    }

    // ------------------------------------------------------------------ withdrawals

    /// Sends the caller's balance to `to`.
    function withdraw(address to) external {
        _send(msg.sender, to);
    }

    /// Sends `account`'s balance to `account` (anyone may push it: no gas needed by the owner).
    function payout(address account) external {
        _send(account, account);
    }

    function _send(address from, address to) internal {
        uint256 amount = balanceOf[from];
        if (amount == 0) return;
        balanceOf[from] = 0;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(from, to, amount);
    }

    // ------------------------------------------------------------------ helpers

    function _modelExists(uint64 model) internal view returns (bool) {
        (bool ok, bytes memory r) = Sys.MODELS.staticcall(abi.encodeWithSignature("exists(uint64)", model));
        return ok && r.length >= 32 && abi.decode(r, (bool));
    }

    function _epoch() internal view returns (uint64) {
        (bool ok, bytes memory r) = Sys.CONSENSUS.staticcall(abi.encodeWithSignature("currentEpoch()"));
        if (!ok || r.length < 32) return 0;
        return abi.decode(r, (uint64));
    }
}
