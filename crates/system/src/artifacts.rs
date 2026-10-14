//! Compiled contracts from `contracts/out` (built by `contracts/build.mjs`, checked in).

use alloy_primitives::Bytes;
use std::sync::OnceLock;

/// A compiled contract.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Init code (constructor), without arguments.
    pub bytecode: Bytes,
    /// Runtime code.
    pub deployed: Bytes,
}

macro_rules! artifact {
    ($fn:ident, $file:literal) => {
        /// Compiled artifact.
        pub fn $fn() -> &'static Artifact {
            static A: OnceLock<Artifact> = OnceLock::new();
            A.get_or_init(|| parse(include_str!(concat!("../../../contracts/out/", $file))))
        }
    };
}

fn parse(json: &str) -> Artifact {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Raw {
        bytecode: Bytes,
        deployed_bytecode: Bytes,
    }
    let r: Raw = serde_json::from_str(json).expect("artifact JSON");
    Artifact { bytecode: r.bytecode, deployed: r.deployed_bytecode }
}

artifact!(staking_manager, "StakingManager.json");
artifact!(consensus_registry, "ConsensusRegistry.json");
artifact!(reward_distributor, "RewardDistributor.json");
artifact!(swarm_storage, "SwarmStorage.json");
artifact!(compute_market, "ComputeMarket.json");
artifact!(bls_harness, "BLSHarness.json");
artifact!(certificates, "Certificates.json");
artifact!(model_registry, "ModelRegistry.json");
artifact!(image_registry, "ImageRegistry.json");
artifact!(tee_collateral, "TeeCollateral.json");
artifact!(tdx_verifier, "TdxVerifier.json");
artifact!(enclave_lease, "EnclaveLease.json");
artifact!(limited_wallet, "LimitedWallet.json");
