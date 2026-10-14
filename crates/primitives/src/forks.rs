//! Hard forks (ADR 0008 §2): protocol rules change only through new node software that activates
//! them at a block height. Each chain id has a fixed table compiled into the binary.
//!
//! The fork id (after EIP-2124) summarises the rules a node runs: `crc32(genesis hash ‖ activation
//! heights already passed)` plus the next scheduled activation. Peers exchange it and drop
//! connections to nodes on incompatible rules, and a node warns its operator when peers announce
//! a fork its software does not know.

use alloy_primitives::{Address, B256};

/// A state change applied at a fork's activation block, before its system calls (e.g. replacing
/// a system contract's code to fix a bug).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrregularChange {
    /// Account.
    pub address: Address,
    /// New runtime code, if replaced.
    pub code: Option<&'static [u8]>,
    /// Storage slots to write (slot, value).
    pub storage: &'static [(B256, B256)],
}

/// A hard fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    /// Name, for humans.
    pub name: &'static str,
    /// First block under the new rules.
    pub activation: u64,
    /// Irregular state changes at `activation`.
    pub changes: &'static [IrregularChange],
}

/// Chain id of the public testnet.
pub const TESTNET_CHAIN_ID: u64 = 8018;

/// ADR 0014: `SwarmStorage` (paid user storage, deal audits) replaces `HistoryRegistry` at the
/// same address. Part of the genesis rules of every chain except the public testnet, which
/// started with `HistoryRegistry` and switches at its `swarm` fork.
pub const SWARM: &str = "swarm";

/// ADR 0011 §7 and ADR 0013: `ModelRegistry`, the TEE contracts and the current `ComputeMarket`
/// (relay fees). Part of the genesis rules of every chain except the public testnet.
pub const TEE: &str = "tee";

/// Init code of `HistoryRegistry` as deployed by the public testnet's genesis (2026-09-26).
/// Pinned: the testnet genesis hash depends on it.
pub const TESTNET_GENESIS_HISTORY_REGISTRY: &[u8] =
    include_bytes!("../../../contracts/forks/8018-genesis/HistoryRegistry.initcode");

/// Init code of `ComputeMarket` as deployed by the public testnet's genesis (2026-09-26).
/// Pinned: the testnet genesis hash depends on it.
pub const TESTNET_GENESIS_COMPUTE_MARKET: &[u8] =
    include_bytes!("../../../contracts/forks/8018-genesis/ComputeMarket.initcode");

/// Runtime code of `SwarmStorage` installed by the testnet's `swarm` fork. Pinned (never rebuilt):
/// a node replaying the fork block must install exactly these bytes.
pub const TESTNET_SWARM_STORAGE: &[u8] =
    include_bytes!("../../../contracts/forks/8018-swarm/SwarmStorage.bin");

/// Activation of the testnet's `swarm` fork: the first block of an epoch (600-block epochs).
pub const TESTNET_SWARM_ACTIVATION: u64 = 2_401;

/// Activation of the testnet's `tee` fork: the first block of epoch 389 (about 2026-10-16 12:20
/// UTC+8).
pub const TESTNET_TEE_ACTIVATION: u64 = 233_401;

/// Runtime code installed by the testnet's `tee` fork. Pinned (never rebuilt): a node replaying
/// the fork block must install exactly these bytes. None of these contracts writes storage in
/// its constructor, and `ComputeMarket` keeps the layout of the genesis version (its new
/// `relays` mapping is declared last), so installing code is all the fork does.
pub mod testnet_tee {
    #[allow(missing_docs)]
    pub const COMPUTE_MARKET: &[u8] =
        include_bytes!("../../../contracts/forks/8018-tee/ComputeMarket.bin");
    #[allow(missing_docs)]
    pub const MODEL_REGISTRY: &[u8] =
        include_bytes!("../../../contracts/forks/8018-tee/ModelRegistry.bin");
    #[allow(missing_docs)]
    pub const IMAGE_REGISTRY: &[u8] =
        include_bytes!("../../../contracts/forks/8018-tee/ImageRegistry.bin");
    #[allow(missing_docs)]
    pub const TEE_COLLATERAL: &[u8] =
        include_bytes!("../../../contracts/forks/8018-tee/TeeCollateral.bin");
    #[allow(missing_docs)]
    pub const TDX_VERIFIER: &[u8] =
        include_bytes!("../../../contracts/forks/8018-tee/TdxVerifier.bin");
    #[allow(missing_docs)]
    pub const ENCLAVE_LEASE: &[u8] =
        include_bytes!("../../../contracts/forks/8018-tee/EnclaveLease.bin");
    #[allow(missing_docs)]
    pub const LIMITED_WALLET: &[u8] =
        include_bytes!("../../../contracts/forks/8018-tee/LimitedWallet.bin");
}

const fn install(address: Address, code: &'static [u8]) -> IrregularChange {
    IrregularChange { address, code: Some(code), storage: &[] }
}

const TESTNET_FORKS: &[Fork] = &[
    Fork {
        name: SWARM,
        activation: TESTNET_SWARM_ACTIVATION,
        changes: &[IrregularChange {
            address: alloy_primitives::address!("0xB017000000000000000000000000000000000005"),
            code: Some(TESTNET_SWARM_STORAGE),
            storage: &[],
        }],
    },
    Fork {
        name: TEE,
        activation: TESTNET_TEE_ACTIVATION,
        changes: &[
            install(
                alloy_primitives::address!("0xB017000000000000000000000000000000000006"),
                testnet_tee::COMPUTE_MARKET,
            ),
            install(
                alloy_primitives::address!("0xB017000000000000000000000000000000000007"),
                testnet_tee::MODEL_REGISTRY,
            ),
            install(
                alloy_primitives::address!("0xB017000000000000000000000000000000000008"),
                testnet_tee::IMAGE_REGISTRY,
            ),
            install(
                alloy_primitives::address!("0xB017000000000000000000000000000000000009"),
                testnet_tee::TEE_COLLATERAL,
            ),
            install(
                alloy_primitives::address!("0xB01700000000000000000000000000000000000A"),
                testnet_tee::TDX_VERIFIER,
            ),
            install(
                alloy_primitives::address!("0xB01700000000000000000000000000000000000B"),
                testnet_tee::ENCLAVE_LEASE,
            ),
            install(
                alloy_primitives::address!("0xB01700000000000000000000000000000000000C"),
                testnet_tee::LIMITED_WALLET,
            ),
        ],
    },
];

/// Hard forks of a chain, in activation order.
pub fn forks(chain_id: u64) -> &'static [Fork] {
    match chain_id {
        TESTNET_CHAIN_ID => TESTNET_FORKS,
        _ => &[],
    }
}

/// Whether the rules named `feature` apply at block `number`: from its fork's activation on a
/// chain that lists the fork, from genesis on every other chain.
pub fn active(chain_id: u64, feature: &str, number: u64) -> bool {
    match forks(chain_id).iter().find(|f| f.name == feature) {
        Some(f) => number >= f.activation,
        None => true,
    }
}

/// Fork identifier (EIP-2124 layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForkId {
    /// CRC32 of the genesis hash and the activations passed.
    pub hash: [u8; 4],
    /// Next activation height known to the node (0: none).
    pub next: u64,
}

impl std::fmt::Display for ForkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", alloy_primitives::hex::encode(self.hash), self.next)
    }
}

impl std::str::FromStr for ForkId {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        let (h, n) = s.split_once('-').ok_or(())?;
        let bytes = alloy_primitives::hex::decode(h).map_err(|_| ())?;
        let hash: [u8; 4] = bytes.try_into().map_err(|_| ())?;
        Ok(Self { hash, next: n.parse().map_err(|_| ())? })
    }
}

/// IEEE CRC32, updated with `data`.
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    crc = !crc;
    for b in data {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Fork hashes after each prefix of `activations` (index 0: genesis only).
fn hashes(genesis: &B256, activations: &[u64]) -> Vec<[u8; 4]> {
    let mut crc = crc32_update(0, genesis.as_slice());
    let mut out = vec![crc.to_be_bytes()];
    for a in activations {
        crc = crc32_update(crc, &a.to_be_bytes());
        out.push(crc.to_be_bytes());
    }
    out
}

/// Distinct activation heights, ascending (forks at genesis do not count).
fn activations(forks: &[Fork]) -> Vec<u64> {
    let mut a: Vec<u64> =
        forks.iter().map(|f| f.activation).filter(|a| *a > 0 && *a != u64::MAX).collect();
    a.sort_unstable();
    a.dedup();
    a
}

/// Fork id of a node at `head` with fork table `forks`.
pub fn fork_id(genesis: &B256, forks: &[Fork], head: u64) -> ForkId {
    let acts = activations(forks);
    let passed = acts.iter().take_while(|a| **a <= head).count();
    let hash = hashes(genesis, &acts)[passed];
    ForkId { hash, next: acts.get(passed).copied().unwrap_or(0) }
}

/// How a peer's fork id relates to ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    /// Same rules (or a peer that is behind and will follow).
    Compatible,
    /// The peer announces a fork this software does not know: upgrade.
    PeerKnowsNewerFork,
    /// Different rules: disconnect.
    Incompatible,
}

/// EIP-2124 validation of `remote` against our table at `head`.
pub fn check(genesis: &B256, forks: &[Fork], head: u64, remote: &ForkId) -> Compatibility {
    let acts = activations(forks);
    let all = hashes(genesis, &acts);
    let passed = acts.iter().take_while(|a| **a <= head).count();
    if remote.hash == all[passed] {
        // Same state. A next fork we do not schedule means newer software on their side; one we
        // have already passed without them knowing it means they are stale.
        if remote.next != 0 && head >= remote.next {
            return Compatibility::Incompatible;
        }
        if remote.next != 0 && !acts.contains(&remote.next) {
            return Compatibility::PeerKnowsNewerFork;
        }
        return Compatibility::Compatible;
    }
    // A past state of ours: the peer is syncing; its next fork must be our next one from there.
    if let Some(i) = all[..passed].iter().position(|h| *h == remote.hash) {
        return if remote.next == acts[i] {
            Compatibility::Compatible
        } else {
            Compatibility::Incompatible
        };
    }
    // A future state of ours (we are behind).
    if all[passed + 1..].contains(&remote.hash) {
        return Compatibility::Compatible;
    }
    Compatibility::Incompatible
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: B256 = B256::repeat_byte(0x11);

    fn table(acts: &[u64]) -> Vec<Fork> {
        acts.iter().map(|a| Fork { name: "f", activation: *a, changes: &[] }).collect()
    }

    #[test]
    fn crc32_matches_the_standard() {
        assert_eq!(crc32_update(0, b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn fork_id_follows_activations() {
        let t = table(&[100, 200]);
        let a = fork_id(&G, &t, 0);
        let b = fork_id(&G, &t, 100);
        let c = fork_id(&G, &t, 250);
        assert_eq!(a.next, 100);
        assert_eq!(b.next, 200);
        assert_eq!(c.next, 0);
        assert!(a.hash != b.hash && b.hash != c.hash);
        assert_eq!(fork_id(&G, &[], 5), ForkId { hash: hashes(&G, &[])[0], next: 0 });
        assert_eq!(a.to_string().parse::<ForkId>().unwrap(), a);
    }

    #[test]
    fn compatibility_rules() {
        let ours = table(&[100, 200]);
        let head = 150;
        let me = fork_id(&G, &ours, head);
        assert_eq!(check(&G, &ours, head, &me), Compatibility::Compatible);
        // A syncing peer still before fork 100 that knows about it.
        let behind = fork_id(&G, &ours, 10);
        assert_eq!(check(&G, &ours, head, &behind), Compatibility::Compatible);
        // A peer before 100 that never heard of it: old software, incompatible.
        let old = fork_id(&G, &[], 10);
        assert_eq!(check(&G, &ours, head, &old), Compatibility::Incompatible);
        // A peer ahead of us (past 200) while we are at 150.
        let ahead = fork_id(&G, &ours, 300);
        assert_eq!(check(&G, &ours, head, &ahead), Compatibility::Compatible);
        // Same state, but the peer schedules a fork at 300 we do not know: upgrade notice.
        let newer = fork_id(&G, &table(&[100, 200, 300]), 250);
        assert_eq!(check(&G, &ours, 250, &newer), Compatibility::PeerKnowsNewerFork);
        // Another genesis.
        let other = fork_id(&B256::repeat_byte(0x22), &ours, head);
        assert_eq!(check(&G, &ours, head, &other), Compatibility::Incompatible);
        // No forks at all (today): equal genesis is all that matters.
        assert_eq!(check(&G, &[], 5, &fork_id(&G, &[], 999)), Compatibility::Compatible);
    }
}
