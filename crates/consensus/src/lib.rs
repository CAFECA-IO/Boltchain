//! Boltchain consensus: two-chain HotStuff with Jolteon's voting and timeout rules.
//!
//! See [`engine`] for the rules. The engine is a pure state machine generic over a signature
//! [`Scheme`]: [`BlsScheme`] (BLS12-381, production) or [`MockScheme`] (simulation).

pub mod audit;
pub mod engine;
pub mod types;

pub use audit::{
    AttestCert, AttestVote, AuditCert, AuditVote, VerdictCert, VerdictVote, attest_msg, audit_msg,
    verdict_msg,
};
pub use engine::{Action, Config, Engine, Persisted};
pub use types::*;

use alloy_primitives::{B256, keccak256};
use bolt_primitives::bls::{self, BlsPublicKey, BlsSecretKey, BlsSignature};
use std::{collections::HashMap, sync::Arc};

/// BLS12-381 signatures; QCs carry one aggregate signature plus a signer bitmap.
#[derive(Clone)]
pub struct BlsScheme {
    keys: Arc<Vec<BlsPublicKey>>,
    /// `keys` decoded once (`None` for an invalid key, which then verifies nothing).
    prepared: Arc<Vec<Option<bls::PreparedKey>>>,
    secrets: Arc<HashMap<ValidatorIndex, BlsSecretKey>>,
}

impl std::fmt::Debug for BlsScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsScheme").field("validators", &self.keys.len()).finish()
    }
}

impl BlsScheme {
    /// `keys[i]` is committee member `i`'s public key (PoP already checked). Every local secret
    /// key whose public key is in `keys` becomes a signer at that index.
    pub fn new(keys: Vec<BlsPublicKey>, local: &[BlsSecretKey]) -> Self {
        let mut secrets = HashMap::new();
        for sk in local {
            let pk = sk.public_key();
            for (i, k) in keys.iter().enumerate() {
                if *k == pk {
                    secrets.insert(i as ValidatorIndex, sk.clone());
                }
            }
        }
        let prepared = keys.iter().map(bls::prepare).collect();
        Self { keys: Arc::new(keys), prepared: Arc::new(prepared), secrets: Arc::new(secrets) }
    }

    /// Committee indices this scheme can sign for.
    pub fn signers(&self) -> Vec<ValidatorIndex> {
        let mut v: Vec<_> = self.secrets.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Public key of member `i`.
    pub fn key(&self, i: ValidatorIndex) -> Option<&BlsPublicKey> {
        self.keys.get(i as usize)
    }
}

impl Scheme for BlsScheme {
    type Sig = BlsSignature;
    type Agg = BlsSignature;

    fn sign(&self, me: ValidatorIndex, msg: &[u8]) -> Self::Sig {
        self.secrets.get(&me).expect("signing requires this validator's key").sign(msg)
    }

    fn verify(&self, signer: ValidatorIndex, msg: &[u8], sig: &Self::Sig) -> bool {
        self.prepared
            .get(signer as usize)
            .and_then(Option::as_ref)
            .is_some_and(|pk| bls::verify_prepared(pk, msg, sig))
    }

    fn aggregate(&self, sigs: &[Self::Sig]) -> Option<Self::Agg> {
        bls::aggregate(sigs)
    }

    fn verify_aggregate(&self, signers: &[ValidatorIndex], msg: &[u8], agg: &Self::Agg) -> bool {
        let Some(pks) = signers
            .iter()
            .map(|i| self.prepared.get(*i as usize).and_then(Option::as_ref))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        bls::fast_aggregate_verify_prepared(&pks, msg, agg)
    }
}

/// Keyed-hash "signatures" for the simulator: cheap, deterministic, and unforgeable within the
/// simulation because byzantine behaviours only ever sign as themselves.
#[derive(Clone, Debug, Default)]
pub struct MockScheme;

fn mock_sig(signer: ValidatorIndex, msg: &[u8]) -> B256 {
    keccak256([&signer.to_be_bytes()[..], msg].concat())
}

impl Scheme for MockScheme {
    type Sig = B256;
    type Agg = Vec<B256>;

    fn sign(&self, me: ValidatorIndex, msg: &[u8]) -> Self::Sig {
        mock_sig(me, msg)
    }

    fn verify(&self, signer: ValidatorIndex, msg: &[u8], sig: &Self::Sig) -> bool {
        mock_sig(signer, msg) == *sig
    }

    fn aggregate(&self, sigs: &[Self::Sig]) -> Option<Self::Agg> {
        Some(sigs.to_vec())
    }

    fn verify_aggregate(&self, signers: &[ValidatorIndex], msg: &[u8], agg: &Self::Agg) -> bool {
        signers.len() == agg.len() && signers.iter().zip(agg).all(|(s, a)| mock_sig(*s, msg) == *a)
    }
}

/// Encodes a message for the wire (dag-cbor).
pub fn encode<S: Scheme>(m: &Message<S>) -> Vec<u8> {
    serde_ipld_dagcbor::to_vec(m).expect("consensus message serializes")
}

/// Decodes a wire message.
pub fn decode<S: Scheme>(b: &[u8]) -> Option<Message<S>> {
    serde_ipld_dagcbor::from_slice(b).ok()
}

/// Encodes a block's parent certificate (the envelope `qc` field). The genesis certificate is
/// encoded as empty bytes.
pub fn encode_cert<S: Scheme>(c: &Cert<S>) -> Vec<u8> {
    if let Cert::Qc(q) = c
        && q.is_genesis()
    {
        return Vec::new();
    }
    serde_ipld_dagcbor::to_vec(c).expect("certificate serializes")
}

/// Decodes an envelope certificate. `None` for empty bytes (genesis child) or garbage.
pub fn decode_cert<S: Scheme>(b: &[u8]) -> Option<Cert<S>> {
    if b.is_empty() {
        return None;
    }
    serde_ipld_dagcbor::from_slice(b).ok()
}

/// (epoch, round, signer bitmap) recorded by a production (BLS) envelope certificate; empty for
/// the genesis child or undecodable bytes. Used by execution for participation rewards.
pub fn cert_votes(b: &[u8]) -> (u64, u64, Vec<u8>) {
    match decode_cert::<BlsScheme>(b) {
        Some(c) => {
            let (e, bm) = c.votes();
            let round = match &c {
                Cert::Qc(q) => q.round,
                Cert::Epoch(p) => p.qc.round,
            };
            (e, round, bm.to_vec())
        }
        None => (0, 0, Vec::new()),
    }
}

#[cfg(test)]
mod tests;
