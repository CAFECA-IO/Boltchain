// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Sys, SystemContract} from "./System.sol";
import {TdxVerifier} from "./TdxVerifier.sol";
import {Bytes} from "./TeeLib.sol";

interface IImageRegistry {
    function allows(uint64 id, uint8 kind, bytes32 m) external view returns (bool);
}

interface ICollateralStatus {
    function tdxStatus(
        bytes6 fmspc,
        uint8[16] calldata compSvn,
        uint16 pcesvn,
        bytes16 teeTcbSvn,
        bytes calldata mrSignerSeam,
        bytes8 seamAttributes
    ) external view returns (uint8 status, uint64 nextUpdate);
    function revoked(bytes32 issuer, bytes32 serial) external view returns (bool);
}

/// @title Leasing remote TEEs to run AI agents (ADR 0013).
/// @notice Operators register machines with an attestation that names the hardware (Intel TDX:
/// verified here by `TdxVerifier`; TPM 2.0 measured-boot devices: endorsed by the verifier
/// panel), and offer them by the hour. A renter escrows payment for an image and an agent
/// package; the enclave proves, bound to fresh keys and this lease, that it runs them; from
/// then on its signing key is the lease's only active enclave. It checkpoints its state about
/// once an hour, each checkpoint paying the operator one hour. Two different states signed for
/// the same version can only come from a broken TEE: the operator's whole bond is slashed and
/// the machine blacklisted.
contract EnclaveLease is SystemContract {
    // ------------------------------------------------------------------ constants

    uint8 public constant TDX = 1;
    uint8 public constant TPM = 3;

    uint256 public constant HOUR = 1 hours;
    /// Notice an operator gives before leaving a lease (charged as usual meanwhile).
    uint256 public constant EXIT_NOTICE = 24 hours;
    /// Missing checkpoints for this long lets the renter move the lease without the operator.
    uint256 public constant ABSENCE = 2 hours;
    /// Earnings withheld into the bond until it reaches BOND_TARGET (as ComputeMarket).
    uint256 public constant BOND_BPS = 2_000;
    uint256 public constant BOND_TARGET = 64 ether;
    uint256 public constant UNBOND_DELAY = 14 days;
    uint256 public constant MAX_RELAY_FEE = 0.1 ether;
    /// A panel request not decided within this time may be retried.
    uint256 public constant REQUEST_TIMEOUT = 1 days;

    bytes32 internal constant CHECKPOINT = keccak256("boltchain/checkpoint/v1");
    bytes32 internal constant MACHINE = keccak256("boltchain/machine/v1");
    bytes32 internal constant ENCLAVE = keccak256("boltchain/enclave/v1");

    // ------------------------------------------------------------------ machines

    struct Machine {
        address operator;
        uint8 kind;
        bool verified;
        bool available;
        uint8 tcbStatus; // TDX: TeeCollateral status at the last check
        uint128 pricePerHour;
        bytes32 machineId; // TDX: keccak256(PPID); TPM: keccak256(EK public key)
        uint32 cpus;
        uint32 memGiB;
        uint32 leases; // active leases
        uint64 registeredAt;
        string gpu;
        string endpoint; // where the operator's enclave host answers (panel challenges)
    }

    /// The TCB of a TDX machine as last attested (for `recheck`).
    struct TdxTcb {
        bytes6 fmspc;
        uint16 pcesvn;
        bytes8 seamAttributes;
        bytes16 teeTcbSvn;
        uint8[16] compSvn;
        bytes mrSignerSeam;
        bytes32 pckIssuer;
        bytes32 pckSerial;
    }

    Machine[] internal machines;
    mapping(uint64 => TdxTcb) internal tdxTcb;
    /// Machine ID → machine index (one operator per machine).
    mapping(bytes32 => uint64) public machineIndex;
    mapping(bytes32 => bool) public blacklisted;

    // ------------------------------------------------------------------ operators

    struct Operator {
        uint256 bond;
        uint256 unbonding;
        uint64 unbondAt;
        uint64 slashedAt;
    }

    mapping(address => Operator) public operators;
    mapping(address => uint256) public balanceOf;
    /// Slashed funds kept locked forever (burned).
    uint256 public burned;

    // ------------------------------------------------------------------ leases

    uint8 public constant PENDING = 1; // waiting for the enclave's attestation
    uint8 public constant VERIFYING = 2; // attestation with the verifier panel
    uint8 public constant ACTIVE = 3;
    uint8 public constant ENDED = 4;

    struct Lease {
        address renter;
        uint64 machine;
        uint64 image;
        uint8 state;
        uint8 minTcb; // worst TCB status accepted (TDX)
        bool degraded; // platform fell below minTcb after activation
        uint128 pricePerHour;
        uint128 escrow;
        uint128 relayFee; // paid per checkpoint/activation to whoever submits it
        uint128 minBond;
        bytes32 agentHash;
        bytes32 nonce; // fresh per activation
        address signer; // the active enclave's signing key
        bytes32 encKey; // its X25519 encryption key
        uint64 version; // last on-chain checkpoint version
        uint64 activatedAt;
        uint64 lastCheckpointAt;
        uint64 lastPaidAt;
        uint64 exitAt; // operator's announced exit (0 = none)
        uint64 hoursPaid;
        bytes32 stateRoot;
        bytes stateCid;
    }

    Lease[] internal leases;
    /// Every enclave key ever active, and for which lease (equivocation evidence).
    mapping(address => uint256) public signerLease;
    /// …and on which machine it ran.
    mapping(address => uint64) public signerMachine;

    // ------------------------------------------------------------------ panel requests

    uint8 public constant REQ_MACHINE = 1;
    uint8 public constant REQ_ACTIVATE = 2;

    struct Request {
        uint8 kind;
        uint8 state; // 1 waiting, 2 approved, 3 rejected
        uint64 machine;
        uint256 lease;
        address signer;
        bytes32 encKey;
        bytes32 evidence; // sha256 of the evidence bundle the panel fetches from the machine
        uint64 epoch;
        uint64 requestedAt;
    }

    Request[] internal requests;
    uint256[] internal unassigned;
    mapping(uint64 => uint32[]) internal panels;

    // ------------------------------------------------------------------ events

    event MachineRegistered(uint64 indexed machine, address indexed operator, uint8 kind, bytes32 machineId);
    event MachineVerified(uint64 indexed machine, bytes32 machineId, uint8 tcbStatus);
    event OfferSet(uint64 indexed machine, uint128 pricePerHour, bool available);
    event LeaseCreated(uint256 indexed lease, address indexed renter, uint64 indexed machine, uint64 image, bytes32 nonce);
    event Activated(uint256 indexed lease, address signer, bytes32 encKey);
    event Checkpoint(uint256 indexed lease, uint64 version, bytes32 stateRoot, bytes stateCid, bool paid);
    event Ended(uint256 indexed lease, uint256 refund);
    event ExitAnnounced(uint256 indexed lease, uint64 exitAt);
    event Migrated(uint256 indexed lease, uint64 from, uint64 to, bytes32 nonce);
    event Degraded(uint256 indexed lease, uint8 tcbStatus);
    event Equivocation(uint256 indexed lease, address signer, uint64 version, address reporter, uint256 slashed);
    event AttestationRequested(uint256 indexed request, uint8 kind, uint64 machine, uint256 lease, bytes32 evidence);
    event PanelAssigned(uint64 indexed epoch, uint256 requests);
    event AttestationRecorded(uint256 indexed request, bool ok, bytes32 machineId);
    event BondChanged(address indexed operator, uint256 bond);

    // ------------------------------------------------------------------ errors

    error BadParams();
    error BadState();
    error NotAllowed();
    error BadSignature();
    error BadAttestation(string why);
    error Taken();
    error Blacklisted();
    error InsufficientBond();
    error TooEarly();

    // ================================================================== machines

    /// Registers a machine. TDX: `attestation` is a TD quote whose REPORT_DATA[0:32] is
    /// `machineBinding(msg.sender)`; verified here. TPM: `attestation` is the sha256 of the
    /// evidence bundle (EK certificate, AK, quote, event log) the panel fetches from `endpoint`.
    function registerMachine(
        uint8 kind,
        bytes calldata attestation,
        string calldata endpoint,
        uint32 cpus,
        uint32 memGiB,
        string calldata gpu
    ) external returns (uint64 m) {
        if (bytes(endpoint).length == 0 || bytes(endpoint).length > 256 || bytes(gpu).length > 128) revert BadParams();
        machines.push();
        m = uint64(machines.length);
        Machine storage mc = machines[m - 1];
        mc.operator = msg.sender;
        mc.kind = kind;
        mc.cpus = cpus;
        mc.memGiB = memGiB;
        mc.gpu = gpu;
        mc.endpoint = endpoint;
        mc.registeredAt = uint64(block.timestamp);
        if (kind == TDX) {
            TdxVerifier.Result memory r = TdxVerifier(Sys.TDX).verify(attestation);
            if (Bytes.word(r.reportData, 0) != machineBinding(msg.sender)) revert BadAttestation("binding");
            _storeTcb(m, r);
            _bindMachine(m, r.machineId);
            mc.tcbStatus = r.tcbStatus;
            emit MachineRegistered(m, msg.sender, kind, r.machineId);
            emit MachineVerified(m, r.machineId, r.tcbStatus);
        } else if (kind == TPM) {
            if (attestation.length != 32) revert BadParams();
            emit MachineRegistered(m, msg.sender, kind, 0);
            _request(REQ_MACHINE, m, 0, address(0), 0, bytes32(attestation));
        } else {
            revert BadParams();
        }
    }

    /// What a machine's registration attestation binds: this chain, this contract, the operator.
    function machineBinding(address operator) public view returns (bytes32) {
        return keccak256(abi.encode(MACHINE, block.chainid, address(this), operator));
    }

    function _bindMachine(uint64 m, bytes32 machineId) internal {
        if (machineId == 0) revert BadAttestation("machine id");
        if (blacklisted[machineId]) revert Blacklisted();
        uint64 prev = machineIndex[machineId];
        if (prev != 0 && prev != m) revert Taken();
        machineIndex[machineId] = m;
        Machine storage mc = machines[m - 1];
        mc.machineId = machineId;
        mc.verified = true;
    }

    function _storeTcb(uint64 m, TdxVerifier.Result memory r) internal {
        TdxTcb storage t = tdxTcb[m];
        t.fmspc = r.fmspc;
        t.pcesvn = r.pcesvn;
        t.teeTcbSvn = r.teeTcbSvn;
        t.compSvn = r.compSvn;
        t.pckIssuer = r.pckIssuer;
        t.pckSerial = r.pckSerial;
        t.mrSignerSeam = r.mrSignerSeam;
        t.seamAttributes = r.seamAttributes;
    }

    /// The operator sets the machine's hourly price and whether it takes new leases.
    function setOffer(uint64 m, uint128 pricePerHour, bool available) external {
        Machine storage mc = _machine(m);
        if (msg.sender != mc.operator) revert NotAllowed();
        if (pricePerHour == 0) revert BadParams();
        mc.pricePerHour = pricePerHour;
        mc.available = available;
        emit OfferSet(m, pricePerHour, available);
    }

    // ================================================================== bonds

    function depositBond() external payable {
        Operator storage o = operators[msg.sender];
        o.bond += msg.value;
        emit BondChanged(msg.sender, o.bond);
    }

    /// Starts unbonding `amount`; it can be withdrawn after UNBOND_DELAY (the evidence window).
    function unbond(uint256 amount) external {
        Operator storage o = operators[msg.sender];
        if (amount == 0 || amount > o.bond) revert BadParams();
        o.bond -= amount;
        o.unbonding += amount;
        o.unbondAt = uint64(block.timestamp + UNBOND_DELAY);
        emit BondChanged(msg.sender, o.bond);
    }

    function claimUnbonded() external {
        Operator storage o = operators[msg.sender];
        if (o.unbonding == 0 || block.timestamp < o.unbondAt) revert TooEarly();
        balanceOf[msg.sender] += o.unbonding;
        o.unbonding = 0;
    }

    function _earn(address op, uint256 amount) internal {
        Operator storage o = operators[op];
        uint256 toBond;
        if (o.bond < BOND_TARGET) {
            toBond = amount * BOND_BPS / 10_000;
            if (o.bond + toBond > BOND_TARGET) toBond = BOND_TARGET - o.bond;
            o.bond += toBond;
        }
        balanceOf[op] += amount - toBond;
    }

    // ================================================================== leases

    /// Rents machine `m` for image `image` running the agent package `agentHash`, escrowing
    /// `msg.value` (at least one hour). `minTcb`: worst TDX TCB status accepted (1 = up to
    /// date). `minBond`: the operator's bond required. `relayFee`: paid out of the escrow to
    /// whoever submits each checkpoint and the activation (operators need no BOLT).
    function createLease(
        uint64 m,
        uint64 image,
        bytes32 agentHash,
        uint8 minTcb,
        uint128 minBond,
        uint128 relayFee
    ) external payable returns (uint256 id) {
        Machine storage mc = _machine(m);
        if (!mc.verified || !mc.available) revert BadState();
        if (blacklisted[mc.machineId]) revert Blacklisted();
        if (operators[mc.operator].bond < minBond) revert InsufficientBond();
        if (relayFee > MAX_RELAY_FEE || msg.value < uint256(mc.pricePerHour) + relayFee || msg.value > type(uint128).max) {
            revert BadParams();
        }
        if (minTcb == 0 || agentHash == 0) revert BadParams();
        leases.push();
        id = leases.length;
        Lease storage l = leases[id - 1];
        l.renter = msg.sender;
        l.machine = m;
        l.image = image;
        l.state = PENDING;
        l.minTcb = minTcb;
        l.pricePerHour = mc.pricePerHour;
        l.escrow = uint128(msg.value);
        l.relayFee = relayFee;
        l.minBond = minBond;
        l.agentHash = agentHash;
        l.nonce = keccak256(abi.encode(block.prevrandao, id, uint256(0)));
        mc.leases++;
        emit LeaseCreated(id, msg.sender, m, image, l.nonce);
    }

    /// Adds to a lease's escrow.
    function topUp(uint256 id) external payable {
        Lease storage l = _lease(id);
        if (l.state == ENDED || msg.value == 0) revert BadState();
        l.escrow += uint128(msg.value);
    }

    /// What an enclave's attestation must bind (TDX REPORT_DATA[0:32], TPM qualifyingData).
    function enclaveBinding(uint256 id, address signer, bytes32 encKey) public view returns (bytes32) {
        return keccak256(abi.encode(ENCLAVE, block.chainid, address(this), id, signer, encKey, leases[id - 1].nonce));
    }

    /// Activates lease `id` with the enclave keys `signer` (secp256k1 address) and `encKey`
    /// (X25519). TDX: `attestation` is a TD quote from the leased machine whose REPORT_DATA is
    /// `enclaveBinding ‖ agentHash` and whose measurement the image lists; anyone may submit it
    /// (and earns the relay fee). TPM: `attestation` is the sha256 of the evidence bundle; the
    /// renter or operator queues it for the panel.
    function activate(uint256 id, address signer, bytes32 encKey, bytes calldata attestation) external {
        Lease storage l = _lease(id);
        if (l.state != PENDING || signer == address(0) || encKey == 0) revert BadState();
        if (signerLease[signer] != 0) revert Taken();
        Machine storage mc = machines[l.machine - 1];
        if (blacklisted[mc.machineId]) revert Blacklisted();
        if (mc.kind == TDX) {
            TdxVerifier.Result memory r = TdxVerifier(Sys.TDX).verify(attestation);
            if (r.machineId != mc.machineId) revert BadAttestation("another machine");
            if (Bytes.word(r.reportData, 0) != enclaveBinding(id, signer, encKey)) revert BadAttestation("binding");
            if (Bytes.word(r.reportData, 32) != l.agentHash) revert BadAttestation("agent");
            if (!IImageRegistry(Sys.IMAGES).allows(l.image, TDX, TdxVerifier(Sys.TDX).measurementOf(r))) {
                revert BadAttestation("measurement");
            }
            if (r.tcbStatus > l.minTcb) revert BadAttestation("TCB");
            _storeTcb(l.machine, r);
            mc.tcbStatus = r.tcbStatus;
            _activate(id, l, signer, encKey);
            _payRelay(l, msg.sender);
        } else {
            if (msg.sender != l.renter && msg.sender != mc.operator) revert NotAllowed();
            if (attestation.length != 32) revert BadParams();
            l.state = VERIFYING;
            _request(REQ_ACTIVATE, l.machine, id, signer, encKey, bytes32(attestation));
        }
    }

    function _activate(uint256 id, Lease storage l, address signer, bytes32 encKey) internal {
        l.signer = signer;
        l.encKey = encKey;
        l.state = ACTIVE;
        l.activatedAt = uint64(block.timestamp);
        l.lastCheckpointAt = uint64(block.timestamp);
        l.lastPaidAt = uint64(block.timestamp);
        signerLease[signer] = id;
        signerMachine[signer] = l.machine;
        emit Activated(id, signer, encKey);
    }

    function _payRelay(Lease storage l, address to) internal {
        uint256 fee = l.relayFee <= l.escrow ? l.relayFee : l.escrow;
        if (fee != 0) {
            l.escrow -= uint128(fee);
            balanceOf[to] += fee;
        }
    }

    /// Digest the enclave signs (EIP-191) for a checkpoint of lease `id`.
    function checkpointDigest(uint256 id, uint64 version, bytes32 stateRoot, bytes32 cidHash, bytes32 seenBlockhash)
        public
        view
        returns (bytes32)
    {
        bytes32 h = keccak256(abi.encode(CHECKPOINT, block.chainid, address(this), id, version, stateRoot, cidHash, seenBlockhash));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    /// Records a checkpoint signed by the lease's active enclave; anyone may submit it (earning
    /// the relay fee). The first checkpoint at least an hour after the last payment pays the
    /// operator one hour. `seenBlock` must be one of the last 256 blocks.
    function checkpoint(
        uint256 id,
        uint64 version,
        bytes calldata stateCid,
        bytes32 stateRoot,
        uint256 seenBlock,
        bytes calldata sig
    ) external {
        Lease storage l = _lease(id);
        if (l.state != ACTIVE) revert BadState();
        if (version <= l.version || stateCid.length == 0 || stateCid.length > 128) revert BadParams();
        bytes32 seen = blockhash(seenBlock);
        if (seen == 0) revert BadParams();
        if (_recover(checkpointDigest(id, version, stateRoot, keccak256(stateCid), seen), sig) != l.signer) {
            revert BadSignature();
        }
        Machine storage mc = machines[l.machine - 1];
        if (blacklisted[mc.machineId]) revert Blacklisted();
        l.version = version;
        l.stateRoot = stateRoot;
        l.stateCid = stateCid;
        l.lastCheckpointAt = uint64(block.timestamp);
        _payRelay(l, msg.sender);
        bool paid;
        if (block.timestamp >= l.lastPaidAt + HOUR && !l.degraded) {
            if (l.escrow >= l.pricePerHour) {
                l.escrow -= l.pricePerHour;
                l.lastPaidAt = uint64(block.timestamp);
                l.hoursPaid++;
                _earn(mc.operator, l.pricePerHour);
                paid = true;
            }
        }
        emit Checkpoint(id, version, stateRoot, stateCid, paid);
        if (l.escrow < l.pricePerHour || (l.exitAt != 0 && block.timestamp >= l.exitAt)) _end(id, l);
    }

    struct Signed {
        bytes32 stateRoot;
        bytes32 cidHash;
        bytes32 seenBlockhash;
        bytes sig;
    }

    /// Two different checkpoints for the same lease and version, both signed by one enclave key
    /// (on chain or intermediate): the TEE is broken. The operator's whole bond is slashed (half
    /// to the reporter, half burned) and the machine blacklisted.
    function reportEquivocation(uint256 id, uint64 version, Signed calldata a, Signed calldata b) external {
        if (a.stateRoot == b.stateRoot && a.cidHash == b.cidHash) revert BadParams();
        address sa = _recover(checkpointDigest(id, version, a.stateRoot, a.cidHash, a.seenBlockhash), a.sig);
        address sb = _recover(checkpointDigest(id, version, b.stateRoot, b.cidHash, b.seenBlockhash), b.sig);
        if (sa != sb || sa == address(0) || signerLease[sa] != id) revert BadSignature();
        Lease storage l = _lease(id);
        Machine storage mc = machines[signerMachine[sa] - 1];
        Operator storage o = operators[mc.operator];
        uint256 slashed = o.bond + o.unbonding;
        o.bond = 0;
        o.unbonding = 0;
        o.slashedAt = uint64(block.timestamp);
        uint256 reward = slashed / 2;
        balanceOf[msg.sender] += reward;
        burned += slashed - reward;
        blacklisted[mc.machineId] = true;
        mc.available = false;
        emit Equivocation(id, sa, version, msg.sender, slashed);
        emit BondChanged(mc.operator, 0);
        if (l.state != ENDED && l.machine == signerMachine[sa]) _end(id, l);
    }

    /// The renter ends the lease at any time; it pays only up to the last checkpoint.
    function terminate(uint256 id) external {
        Lease storage l = _lease(id);
        if (msg.sender != l.renter) revert NotAllowed();
        if (l.state == ENDED) revert BadState();
        _end(id, l);
    }

    /// The operator announces leaving the lease after EXIT_NOTICE (billed as usual meanwhile).
    function exit(uint256 id) external {
        Lease storage l = _lease(id);
        if (msg.sender != machines[l.machine - 1].operator) revert NotAllowed();
        if (l.state == ENDED || l.exitAt != 0) revert BadState();
        if (l.state != ACTIVE) {
            _end(id, l); // never started: nothing to give notice for
            return;
        }
        l.exitAt = uint64(block.timestamp + EXIT_NOTICE);
        emit ExitAnnounced(id, l.exitAt);
    }

    /// Ends a lease whose operator's notice has run out.
    function finish(uint256 id) external {
        Lease storage l = _lease(id);
        if (l.state == ENDED || l.exitAt == 0 || block.timestamp < l.exitAt) revert BadState();
        _end(id, l);
    }

    function _end(uint256 id, Lease storage l) internal {
        uint256 refund = l.escrow;
        l.escrow = 0;
        l.state = ENDED;
        Machine storage mc = machines[l.machine - 1];
        if (mc.leases != 0) mc.leases--;
        balanceOf[l.renter] += refund;
        emit Ended(id, refund);
    }

    /// The renter moves the lease to machine `to`, keeping its escrow, image and checkpoint
    /// version: the new enclave must attest before it becomes active, and the old enclave's key
    /// is no longer accepted. Allowed while the lease is pending, degraded, its operator is
    /// leaving or was slashed, or no checkpoint arrived for ABSENCE.
    function migrate(uint256 id, uint64 to) external {
        Lease storage l = _lease(id);
        if (msg.sender != l.renter) revert NotAllowed();
        if (l.state == ENDED || l.state == VERIFYING) revert BadState();
        Machine storage old = machines[l.machine - 1];
        bool may = l.state == PENDING || l.degraded || l.exitAt != 0 || operators[old.operator].slashedAt != 0
            || blacklisted[old.machineId] || block.timestamp >= l.lastCheckpointAt + ABSENCE;
        if (!may) revert TooEarly();
        Machine storage mc = _machine(to);
        if (to == l.machine || !mc.verified || !mc.available || blacklisted[mc.machineId]) revert BadState();
        if (operators[mc.operator].bond < l.minBond) revert InsufficientBond();
        if (l.escrow < mc.pricePerHour) revert BadParams();
        if (old.leases != 0) old.leases--;
        mc.leases++;
        uint64 from = l.machine;
        l.machine = to;
        l.pricePerHour = mc.pricePerHour;
        l.state = PENDING;
        l.signer = address(0);
        l.encKey = 0;
        l.degraded = false;
        l.exitAt = 0;
        l.nonce = keccak256(abi.encode(block.prevrandao, id, l.nonce));
        emit Migrated(id, from, to, l.nonce);
    }

    /// Re-evaluates a TDX lease's platform against the current collateral: a status worse than
    /// the lease accepts, or a revoked PCK certificate, marks it degraded (no more payments; the
    /// renter may migrate). Anyone may call it.
    function recheck(uint256 id) external returns (uint8 status) {
        Lease storage l = _lease(id);
        Machine storage mc = machines[l.machine - 1];
        if (l.state != ACTIVE || mc.kind != TDX) revert BadState();
        TdxTcb storage t = tdxTcb[l.machine];
        ICollateralStatus col = ICollateralStatus(Sys.COLLATERAL);
        (status,) = col.tdxStatus(t.fmspc, t.compSvn, t.pcesvn, t.teeTcbSvn, t.mrSignerSeam, t.seamAttributes);
        if (col.revoked(t.pckIssuer, t.pckSerial)) status = 7;
        mc.tcbStatus = status;
        if (status == 0 || status > l.minTcb) {
            l.degraded = true;
            emit Degraded(id, status);
        }
    }

    // ================================================================== verifier panel

    function _request(uint8 kind, uint64 m, uint256 leaseId, address signer, bytes32 encKey, bytes32 evidence) internal {
        requests.push(
            Request({
                kind: kind,
                state: 1,
                machine: m,
                lease: leaseId,
                signer: signer,
                encKey: encKey,
                evidence: evidence,
                epoch: 0,
                requestedAt: uint64(block.timestamp)
            })
        );
        uint256 r = requests.length;
        unassigned.push(r);
        emit AttestationRequested(r, kind, m, leaseId, evidence);
    }

    /// Every block with waiting attestation requests: the node assigns them to the current
    /// epoch's verifier panel (drawn once per epoch, as for ComputeMarket disputes).
    function assignAttestations(uint64 epoch, uint32[] calldata members) external onlySystem {
        uint256 n = unassigned.length;
        if (n == 0) return;
        // Requests are assigned as they come; the epoch's panel is fixed by the first.
        if (panels[epoch].length == 0) panels[epoch] = members;
        for (uint256 i = 0; i < n; i++) {
            requests[unassigned[i] - 1].epoch = epoch;
        }
        delete unassigned;
        emit PanelAssigned(epoch, n);
    }

    /// The panel's certified result (checked by the node against the panel's keys): whether the
    /// evidence is genuine and matches, and the machine ID it names (keccak256 of the EK key).
    function recordAttestation(uint256 r, bool ok, bytes32 machineId) external onlySystem returns (bool) {
        if (r == 0 || r > requests.length) return false;
        Request storage q = requests[r - 1];
        if (q.state != 1 || q.epoch == 0) return false;
        Machine storage mc = machines[q.machine - 1];
        if (ok && q.kind == REQ_MACHINE) {
            ok = machineId != 0 && !blacklisted[machineId]
                && (machineIndex[machineId] == 0 || machineIndex[machineId] == q.machine);
            if (ok) {
                _bindMachine(q.machine, machineId);
                emit MachineVerified(q.machine, machineId, 0);
            }
        } else if (q.kind == REQ_ACTIVATE) {
            Lease storage l = leases[q.lease - 1];
            ok = ok && machineId == mc.machineId && !blacklisted[machineId] && l.state == VERIFYING
                && l.machine == q.machine && signerLease[q.signer] == 0;
            if (l.state == VERIFYING) {
                if (ok) {
                    _activate(q.lease, l, q.signer, q.encKey);
                } else {
                    l.state = PENDING;
                }
            }
        }
        q.state = ok ? 2 : 3;
        emit AttestationRecorded(r, ok, machineId);
        return true;
    }

    /// A panel request nobody decided within REQUEST_TIMEOUT is dropped; an activation goes back
    /// to pending so it can be retried.
    function expireRequest(uint256 r) external {
        Request storage q = requests[r - 1];
        if (q.state != 1 || block.timestamp < q.requestedAt + REQUEST_TIMEOUT) revert TooEarly();
        q.state = 3;
        if (q.kind == REQ_ACTIVATE) {
            Lease storage l = leases[q.lease - 1];
            if (l.state == VERIFYING) l.state = PENDING;
        }
        emit AttestationRecorded(r, false, 0);
    }

    // ================================================================== withdrawals

    function withdraw(address to) external {
        _send(msg.sender, to);
    }

    /// Pushes `account`'s balance to it (anyone may: the owner needs no gas).
    function payout(address account) external {
        _send(account, account);
    }

    function _send(address from, address to) internal {
        uint256 amount = balanceOf[from];
        if (amount == 0) revert BadParams();
        balanceOf[from] = 0;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert BadParams();
    }

    // ================================================================== views

    /// The enclave key currently acting for lease `id` (0 unless active and healthy); the
    /// limited wallet accepts session calls from it.
    function activeSigner(uint256 id) external view returns (address) {
        if (id == 0 || id > leases.length) return address(0);
        Lease storage l = leases[id - 1];
        if (l.state != ACTIVE || l.degraded) return address(0);
        if (blacklisted[machines[l.machine - 1].machineId]) return address(0);
        return l.signer;
    }

    function lease(uint256 id) external view returns (Lease memory) {
        return _lease(id);
    }

    function machine(uint64 m) external view returns (Machine memory) {
        return _machine(m);
    }

    function request(uint256 r) external view returns (Request memory) {
        return requests[r - 1];
    }

    function leaseCount() external view returns (uint256) {
        return leases.length;
    }

    function machineCount() external view returns (uint256) {
        return machines.length;
    }

    function requestCount() external view returns (uint256) {
        return requests.length;
    }

    function pendingAttestations() external view returns (uint256[] memory) {
        return unassigned;
    }

    function panel(uint64 epoch) external view returns (uint32[] memory) {
        return panels[epoch];
    }

    // ================================================================== internal

    function _machine(uint64 m) internal view returns (Machine storage) {
        if (m == 0 || m > machines.length) revert BadParams();
        return machines[m - 1];
    }

    function _lease(uint256 id) internal view returns (Lease storage) {
        if (id == 0 || id > leases.length) revert BadParams();
        return leases[id - 1];
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
}
