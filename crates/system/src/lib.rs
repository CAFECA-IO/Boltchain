//! Boltchain system contracts: compiled artifacts, genesis deployment, ABI bindings, the pre-block
//! epoch hooks and committee sampling (ADR 0006).

pub mod abi;
pub mod addresses;
pub mod artifacts;
pub mod committee;
pub mod evidence;
pub mod genesis;
pub mod history;
pub mod hooks;
pub mod queries;

pub use committee::Committee;
pub use genesis::{genesis_alloc, genesis_hash, genesis_header, genesis_state_root};
pub use hooks::{AuditResult, CertVotes, EpochRules, HistoryInputs, Phase, Producer, pre_block};

#[cfg(test)]
mod certificate_tests;
#[cfg(test)]
mod compute_tests;
#[cfg(test)]
mod deal_tests;
#[cfg(test)]
mod storage_tests;
#[cfg(test)]
mod tee_tests;
#[cfg(test)]
mod tests;
