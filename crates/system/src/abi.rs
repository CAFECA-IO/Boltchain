//! ABI bindings for the calls the node makes (and tests use).

#![allow(missing_docs)]
#![allow(clippy::too_many_arguments)] // ICertificates::issue

use alloy_sol_types::sol;

sol! {
    interface IStakingManager {
        enum Status { None, Active, Exiting, Slashed, Withdrawn }

        function registerGenesis(bytes pubkey, address owner, address feeRecipient, uint256 stake)
            external returns (uint32 id);
        function register(bytes pubkey, bytes pubkeyPoint, bytes pop, address feeRecipient)
            external payable returns (uint32 id);
        function deposit(uint32 id) external payable;
        function requestExit(uint32 id) external;
        function withdraw(uint32 id) external;
        function setFeeRecipient(uint32 id, address feeRecipient) external;

        function snapshot(uint64 minAge) external view returns (uint32[] ids, uint256[] stakes);
        function stakerStats() external view returns (uint256 stakers, uint256 total);
        function maturedStake(uint32 id, uint64 minAge) external view returns (uint256);
        function keysOf(uint32[] ids) external view returns (bytes pubkeys, address[] recipients);
        function pubkeyOf(uint32 id) external view returns (bytes);
        function totalActiveStake() external view returns (uint256);
        function deadStake() external view returns (uint256);
        function penalize(uint32 id, uint256 bps, address reporter) external returns (uint256);
        function count() external view returns (uint32);
        function idOfPubkey(bytes32 h) external view returns (uint32);
        function validator(uint32 id) external view returns (
            address owner, address feeRecipient, uint256 stake, Status status, uint64 exitEpoch,
            bytes pubkey);
    }

    interface IConsensusRegistry {
        function initialize(uint32[] memberIds, uint16[] weights, bytes seats) external;
        function beginEpoch(uint64 epoch, bool checkpointMet, bool posMet, uint64 streakRequired)
            external returns (bool cpScheduled, uint64 firstCheckpointEpoch, bool scheduled, uint64 firstPosEpoch);
        function setCommittee(uint64 epoch, uint32[] memberIds, uint16[] weights, bytes seats) external;
        function phase() external view returns (bool checkpointScheduled, uint64 checkpointEpoch,
            bool posScheduled, uint64 posEpoch, uint64 checkpointStreak, uint64 thresholdStreak);
        function currentEpoch() external view returns (uint64);
        function committee(uint64 epoch) external view returns (uint32[] ids, uint16[] weights, bytes seats);
        function submitEvidence(uint32 id, bytes pubkeyPoint, bytes msgA, bytes sigA, bytes msgB, bytes sigB)
            external returns (uint256 slashed);
        function slashBps() external view returns (uint256);
    }

    interface IRewardDistributor {
        function initialize(uint256 genesisSupply) external;
        function onBlock(uint256 burned, uint256 minted, uint64 certEpoch, uint64 certRound, bytes bitmap)
            external;
        function settle(uint64 epoch, uint256 emission) external returns (uint256 paid);
        function preview(uint64 epoch, uint256 emission) external view returns (uint256 paid);
        function claim(uint32 id) external returns (uint256 amount);
        function supply() external view returns (uint256);
        function rewards(uint32 id) external view returns (uint256);
        function votesOf(uint64 epoch, uint256 index) external view returns (uint256);
        function lastRecordedRound(uint64 epoch) external view returns (uint64);
        function settleStorage(uint64 epoch, uint256 emission) external returns (uint256 paid);
        function previewStorage(uint64 epoch, uint256 emission) external view returns (uint256);
    }

    interface ISwarmStorage {
        function recordEpoch(uint64 epoch, bytes cid) external;
        function epochIndex(uint64 epoch) external view returns (bytes);
        function indexedEpochs() external view returns (uint64);
        function setPeer(uint32 id, bytes peerId) external;
        function peerOf(uint32 id) external view returns (bytes);
        function beginAudits(uint64 epoch, uint32[] panel, uint32[] providers, uint64[] targets, uint64[] heights)
            external;
        function recordAudit(uint64 epoch, uint16 task, bool ok) external returns (bool);
        function audits(uint64 epoch) external view returns (uint32[] panel, uint32[] providers,
            uint64[] targets, uint64[] heights, uint8[] states);
        function passed(uint64 epoch) external view returns (uint32[]);
        function registerStorage(bytes peerId) external returns (uint32);
        function registerStorageFor(address account, bytes peerId, uint256 deadline, bytes sig)
            external returns (uint32);
        function registrationDigest(address account, bytes peerId, uint256 deadline)
            external view returns (bytes32);
        function activeStorageProviders() external view returns (uint32[]);
        function storageProvider(uint32 id) external view returns (address account, bool active,
            uint64 exitAt, uint256 bond);
        function storageIdsOf(address account) external view returns (uint32[]);
        function setStoragePeer(uint32 id, bytes peerId) external;
        function exitStorage(uint32 id) external;
        function releaseStorageBond(uint32 id) external;
        function nonces(address account) external view returns (uint256);
        function depositEarnings(uint32 id) external payable;
        function depositBond(uint32 id) external payable;
        function addDealAudits(uint64 epoch, uint32[] providers, uint64[] dealIds, uint64[] indexes_)
            external;
        function taskKinds(uint64 epoch) external view returns (uint8[] kinds);
        function offerStorage(uint32 id, uint64 capacityMiB, uint128 minPrice) external;
        function closeOffer(uint32 id) external;
        function offer(uint32 id) external view returns (uint64 capacityMiB, uint64 usedMiB,
            uint128 minPrice, bool open, uint256 committed);
        function offerList() external view returns (uint32[]);
        function createDeal(bytes root, uint64 blocks, uint64 size, uint8 replicas, uint64 epochs,
            uint128 price) external payable returns (uint256 id);
        function extendDeal(uint256 id, uint64 epochs) external payable;
        function cancelDeal(uint256 id) external;
        function claim(uint256 id, uint256 slot) external;
        function closeDeal(uint256 id) external;
        function repair(uint256 id, uint256 slot) external;
        function deal(uint256 id) external view returns (address owner, bytes root, uint64 blocks,
            uint64 size, uint8 replicas, uint64 startEpoch, uint64 endEpoch, uint128 price,
            uint128 perEpoch, uint256 escrow, bool closed);
        function dealSlots(uint256 id) external view returns (uint32[] providers, uint64[] since,
            uint64[] paidThrough, bool[] open);
        function dealsOf(uint32 id) external view returns (uint256[]);
        function dealCount() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function withdraw(address to) external;
        function payout(address account) external;
    }

    interface IComputeMarket {
        struct Job {
            address requester;
            address provider;
            uint8 state;
            uint64 model;
            uint64 deadline;
            uint64 window;
            uint64 deliveredAt;
            uint64 tokensIn;
            uint64 tokensOut;
            uint64 maxIn;
            uint64 maxOut;
            uint128 priceIn;
            uint128 priceOut;
            uint128 relayFee;
            uint128 escrow;
            bytes input;
            bytes output;
        }
        function register(bytes32 encKey, bytes peerId) external;
        function registerFor(address provider_, bytes32 encKey, bytes peerId, uint256 fee, uint256 deadline,
            bytes sig) external;
        function setEncryptionKey(bytes32 key) external;
        function encryptionKey(address account) external view returns (bytes32);
        function requestExit() external;
        function releaseBond() external;
        function provider(address p) external view returns (bool registered, bytes peerId, uint256 bond,
            uint256 debt, uint32 jobsDone, uint32 faults, uint64 exitEpoch);
        function jobLimit(address p) external view returns (uint256);
        function actionDigest(bytes32 action, address signer, bytes data, uint256 deadline)
            external view returns (bytes32);
        function nonces(address account) external view returns (uint256);
        function post(address provider_, uint64 model, bytes input, uint128 priceIn, uint128 priceOut,
            uint64 maxIn, uint64 maxOut, uint64 deadline, uint64 window, uint128 relayFee)
            external payable returns (uint256 id);
        function accept(uint256 id) external;
        function acceptFor(uint256 id, address provider_, uint128 fee, uint256 deadline, bytes sig) external;
        function shareInput(uint256 id, bytes input) external;
        function deliver(uint256 id, bytes output, uint64 tokensIn, uint64 tokensOut) external;
        function deliverFor(uint256 id, address provider_, bytes output, uint64 tokensIn, uint64 tokensOut,
            uint128 fee, uint256 deadline, bytes sig) external;
        function relays(uint256 id) external view returns (address acceptRelayer, uint128 acceptFee,
            address deliverRelayer, uint128 deliverFee);
        function settle(uint256 id) external;
        function refund(uint256 id) external;
        function dispute(uint256 id, bytes reason) external payable;
        function assignDisputes(uint64 epoch, uint32[] members) external;
        function recordVerdict(uint256 id, bool providerAtFault) external returns (bool);
        function expireDispute(uint256 id) external;
        function job(uint256 id) external view returns (Job);
        function jobCount() external view returns (uint256);
        function panel(uint64 epoch) external view returns (uint32[]);
        function pendingDisputes() external view returns (uint256[]);
        function disputes(uint256 id) external view returns (uint64 openedAt, uint64 panelEpoch, bytes reason);
        function balanceOf(address account) external view returns (uint256);
        function withdraw(address to) external;
        function payout(address account) external;
    }

    interface IModelRegistry {
        struct Model {
            address registrant;
            uint64 registeredAt;
            uint64 parameters;
            uint32 vramMiB;
            string name;
            bytes weights;
            bytes tokenizer;
            string runtime;
        }
        event ModelRegistered(uint64 indexed id, address indexed registrant, string name, bytes weights);
        function register(string name, bytes weights, bytes tokenizer, string runtime, uint64 parameters,
            uint32 vramMiB) external returns (uint64 id);
        function setSupport(uint64 id, bool serving) external;
        function exists(uint64 id) external view returns (bool);
        function model(uint64 id) external view returns (Model);
        function modelCount() external view returns (uint256);
        function serves(uint64 id, address provider) external view returns (bool);
        function providerCount(uint64 id) external view returns (uint32);
    }

    interface IBLSHarness {
        function hashToG2(bytes message, bytes dst) external view returns (bytes);
        function expand(bytes message, bytes dst) external pure returns (bytes);
        function verify(bytes pk, bytes message, bytes sig) external view returns (bool);
        function verifyPop(bytes pk, bytes pubkey, bytes pop) external view returns (bool);
        function compress(bytes pk) external pure returns (bytes);
    }

    /// Evidence certificates (ADR 0016); an ordinary contract, not a system contract.
    interface ICertificates {
        struct Certificate {
            address issuer;
            uint64 issuedAt;
            uint64 blockNumber;
            uint32 files;
            bool publicFiles;
            bytes32 root;
            uint256 deal;
            bytes manifest;
        }
        event Issued(bytes10 indexed code, address indexed issuer, bytes32 root, uint256 deal, bool publicFiles, bytes32[] keccak, bytes32[] sha, uint64[] sizes, bytes manifest, bytes dealRoot);
        function codeOf(bytes32 root, address issuer, bytes32 salt) external pure returns (bytes10);
        function leafOf(bytes32 k, bytes32 s, uint64 size) external pure returns (bytes32);
        function rootOf(bytes32[] k, bytes32[] s, uint64[] sizes) external pure returns (bytes32);
        function issue(bytes32 salt, bytes32[] k, bytes32[] s, uint64[] sizes, bool publicFiles, bytes manifest, bytes dealRoot, uint64 blocks, uint64 size, uint8 replicas, uint64 epochs, uint128 price) external payable returns (bytes10 code);
        function extend(bytes10 code, uint64 epochs) external payable;
        function certificate(bytes10 code) external view returns (Certificate memory);
        function codeOfDeal(bytes32 dealRootHash) external view returns (bytes10);
        function count() external view returns (uint256);
    }
}
