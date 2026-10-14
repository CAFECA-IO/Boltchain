//! Panel votes and certificates. Storage audits (ADR 0009): the epoch's audit panel (16 committee
//! members) fetches each task's data from its provider and signs the outcome. Compute verdicts
//! (ADR 0011): the verifier panel a dispute was assigned to signs whether the provider was at
//! fault. More than 2/3 of a panel agreeing form a certificate that block producers include (in
//! the envelope's `audits` list) and the chain verifies before recording it.

use crate::bitmap;
use bolt_primitives::bls::{self, BlsPublicKey, BlsSecretKey, BlsSignature};
use serde::{Deserialize, Serialize};

/// The message an auditor signs.
pub fn audit_msg(chain_id: u64, epoch: u64, task: u16, passed: bool) -> Vec<u8> {
    [
        b"boltchain/audit/v1".as_slice(),
        &chain_id.to_be_bytes(),
        &epoch.to_be_bytes(),
        &task.to_be_bytes(),
        &[passed as u8],
    ]
    .concat()
}

/// One auditor's vote (gossiped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVote {
    /// Epoch of the task.
    pub epoch: u64,
    /// Task index.
    pub task: u16,
    /// Outcome.
    pub passed: bool,
    /// Index of the auditor in the epoch's panel.
    pub member: u16,
    /// Signature over [`audit_msg`].
    pub sig: BlsSignature,
}

impl AuditVote {
    /// Signs a vote.
    pub fn sign(
        key: &BlsSecretKey,
        chain_id: u64,
        epoch: u64,
        task: u16,
        passed: bool,
        member: u16,
    ) -> Self {
        Self {
            epoch,
            task,
            passed,
            member,
            sig: key.sign(&audit_msg(chain_id, epoch, task, passed)),
        }
    }

    /// dag-cbor.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("vote encodes")
    }

    /// From dag-cbor.
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(b).ok()
    }

    /// Whether the signature is `panel[member]`'s.
    pub fn verify(&self, chain_id: u64, panel: &[BlsPublicKey]) -> bool {
        panel.get(self.member as usize).is_some_and(|pk| {
            bls::verify(pk, &audit_msg(chain_id, self.epoch, self.task, self.passed), &self.sig)
        })
    }
}

/// A panel certificate: more than 2/3 of the panel signed the same outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCert {
    /// Epoch of the task.
    pub epoch: u64,
    /// Task index.
    pub task: u16,
    /// Outcome.
    pub passed: bool,
    /// Signers, as a bitmap over the panel.
    #[serde(with = "serde_bytes")]
    pub signers: Vec<u8>,
    /// Aggregate signature.
    pub sig: BlsSignature,
}

impl AuditCert {
    /// Aggregates `votes` (same epoch, task and outcome; distinct members) for a panel of `n`.
    pub fn aggregate(votes: &[AuditVote], n: usize) -> Option<Self> {
        let first = votes.first()?;
        if votes
            .iter()
            .any(|v| v.epoch != first.epoch || v.task != first.task || v.passed != first.passed)
        {
            return None;
        }
        let mut members: Vec<u16> = votes.iter().map(|v| v.member).collect();
        members.sort_unstable();
        members.dedup();
        if members.len() != votes.len() || members.len() * 3 <= n * 2 {
            return None;
        }
        let sigs: Vec<BlsSignature> = votes.iter().map(|v| v.sig).collect();
        Some(Self {
            epoch: first.epoch,
            task: first.task,
            passed: first.passed,
            signers: bitmap::encode(&members, n),
            sig: bls::aggregate(&sigs)?,
        })
    }

    /// dag-cbor.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("certificate encodes")
    }

    /// From dag-cbor.
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(b).ok()
    }

    /// Whether more than 2/3 of `panel` signed this outcome.
    pub fn verify(&self, chain_id: u64, panel: &[BlsPublicKey]) -> bool {
        let signers = bitmap::decode(&self.signers);
        if signers.len() * 3 <= panel.len() * 2
            || signers.iter().any(|i| *i as usize >= panel.len())
        {
            return false;
        }
        let pks: Vec<BlsPublicKey> = signers.iter().map(|i| panel[*i as usize]).collect();
        bls::fast_aggregate_verify(
            &pks,
            &audit_msg(chain_id, self.epoch, self.task, self.passed),
            &self.sig,
        )
    }
}

/// The message a verifier signs for a compute dispute.
pub fn verdict_msg(chain_id: u64, epoch: u64, job: u64, at_fault: bool) -> Vec<u8> {
    [
        b"boltchain/verdict/v1".as_slice(),
        &chain_id.to_be_bytes(),
        &epoch.to_be_bytes(),
        &job.to_be_bytes(),
        &[at_fault as u8],
    ]
    .concat()
}

/// One verifier's vote on a compute dispute (gossiped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictVote {
    /// Epoch whose verifier panel decides the dispute.
    pub epoch: u64,
    /// Disputed job id.
    pub job: u64,
    /// Whether the provider was at fault.
    pub fault: bool,
    /// Index of the verifier in the epoch's panel.
    pub member: u16,
    /// Signature over [`verdict_msg`].
    pub sig: BlsSignature,
}

impl VerdictVote {
    /// Signs a vote.
    pub fn sign(
        key: &BlsSecretKey,
        chain_id: u64,
        epoch: u64,
        job: u64,
        fault: bool,
        member: u16,
    ) -> Self {
        Self { epoch, job, fault, member, sig: key.sign(&verdict_msg(chain_id, epoch, job, fault)) }
    }

    /// dag-cbor.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("vote encodes")
    }

    /// From dag-cbor.
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(b).ok()
    }

    /// Whether the signature is `panel[member]`'s.
    pub fn verify(&self, chain_id: u64, panel: &[BlsPublicKey]) -> bool {
        panel.get(self.member as usize).is_some_and(|pk| {
            bls::verify(pk, &verdict_msg(chain_id, self.epoch, self.job, self.fault), &self.sig)
        })
    }
}

/// A verifier-panel certificate on a compute dispute. Encoded with a `job` field (an
/// [`AuditCert`] has `task`), so the two never decode as each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictCert {
    /// Epoch whose panel decided.
    pub epoch: u64,
    /// Disputed job id.
    pub job: u64,
    /// Whether the provider was at fault.
    pub fault: bool,
    /// Signers, as a bitmap over the panel.
    #[serde(with = "serde_bytes")]
    pub signers: Vec<u8>,
    /// Aggregate signature.
    pub sig: BlsSignature,
}

impl VerdictCert {
    /// Aggregates `votes` (same epoch, job and verdict; distinct members) for a panel of `n`.
    pub fn aggregate(votes: &[VerdictVote], n: usize) -> Option<Self> {
        let first = votes.first()?;
        if votes
            .iter()
            .any(|v| v.epoch != first.epoch || v.job != first.job || v.fault != first.fault)
        {
            return None;
        }
        let mut members: Vec<u16> = votes.iter().map(|v| v.member).collect();
        members.sort_unstable();
        members.dedup();
        if members.len() != votes.len() || members.len() * 3 <= n * 2 {
            return None;
        }
        let sigs: Vec<BlsSignature> = votes.iter().map(|v| v.sig).collect();
        Some(Self {
            epoch: first.epoch,
            job: first.job,
            fault: first.fault,
            signers: bitmap::encode(&members, n),
            sig: bls::aggregate(&sigs)?,
        })
    }

    /// dag-cbor.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("certificate encodes")
    }

    /// From dag-cbor.
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(b).ok()
    }

    /// Whether more than 2/3 of `panel` signed this verdict.
    pub fn verify(&self, chain_id: u64, panel: &[BlsPublicKey]) -> bool {
        let signers = bitmap::decode(&self.signers);
        if signers.len() * 3 <= panel.len() * 2
            || signers.iter().any(|i| *i as usize >= panel.len())
        {
            return false;
        }
        let pks: Vec<BlsPublicKey> = signers.iter().map(|i| panel[*i as usize]).collect();
        bls::fast_aggregate_verify(
            &pks,
            &verdict_msg(chain_id, self.epoch, self.job, self.fault),
            &self.sig,
        )
    }
}

/// The message a verifier signs for a TEE attestation request (ADR 0013 §6.4): whether the
/// evidence is genuine and matches, and the machine ID it names (zero when refused).
pub fn attest_msg(chain_id: u64, epoch: u64, request: u64, ok: bool, machine: &[u8; 32]) -> Vec<u8> {
    [
        b"boltchain/attest/v1".as_slice(),
        &chain_id.to_be_bytes(),
        &epoch.to_be_bytes(),
        &request.to_be_bytes(),
        &[ok as u8],
        machine,
    ]
    .concat()
}

/// One verifier's vote on an attestation request (gossiped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestVote {
    /// Epoch whose verifier panel decides.
    pub epoch: u64,
    /// `EnclaveLease` request id.
    pub request: u64,
    /// Whether the evidence was accepted.
    pub ok: bool,
    /// The machine ID (keccak256 of the EK public key); zero when refused.
    #[serde(with = "serde_bytes")]
    pub machine: Vec<u8>,
    /// Index of the verifier in the epoch's panel.
    pub member: u16,
    /// Signature over [`attest_msg`].
    pub sig: BlsSignature,
}

fn machine32(m: &[u8]) -> Option<[u8; 32]> {
    m.try_into().ok()
}

impl AttestVote {
    /// Signs a vote.
    pub fn sign(
        key: &BlsSecretKey,
        chain_id: u64,
        epoch: u64,
        request: u64,
        ok: bool,
        machine: [u8; 32],
        member: u16,
    ) -> Self {
        Self {
            epoch,
            request,
            ok,
            machine: machine.to_vec(),
            member,
            sig: key.sign(&attest_msg(chain_id, epoch, request, ok, &machine)),
        }
    }

    /// dag-cbor.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("vote encodes")
    }

    /// From dag-cbor.
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(b).ok()
    }

    /// Whether the signature is `panel[member]`'s.
    pub fn verify(&self, chain_id: u64, panel: &[BlsPublicKey]) -> bool {
        let Some(m) = machine32(&self.machine) else { return false };
        panel.get(self.member as usize).is_some_and(|pk| {
            bls::verify(pk, &attest_msg(chain_id, self.epoch, self.request, self.ok, &m), &self.sig)
        })
    }
}

/// A verifier-panel certificate on an attestation request. Its `request` field keeps it from
/// decoding as an [`AuditCert`] or a [`VerdictCert`] (and the reverse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestCert {
    /// Epoch whose panel decided.
    pub epoch: u64,
    /// `EnclaveLease` request id.
    pub request: u64,
    /// Whether the evidence was accepted.
    pub ok: bool,
    /// The machine ID; zero when refused.
    #[serde(with = "serde_bytes")]
    pub machine: Vec<u8>,
    /// Signers, as a bitmap over the panel.
    #[serde(with = "serde_bytes")]
    pub signers: Vec<u8>,
    /// Aggregate signature.
    pub sig: BlsSignature,
}

impl AttestCert {
    /// Aggregates `votes` (same epoch, request, result; distinct members) for a panel of `n`.
    pub fn aggregate(votes: &[AttestVote], n: usize) -> Option<Self> {
        let first = votes.first()?;
        if votes.iter().any(|v| {
            v.epoch != first.epoch || v.request != first.request || v.ok != first.ok || v.machine != first.machine
        }) {
            return None;
        }
        let mut members: Vec<u16> = votes.iter().map(|v| v.member).collect();
        members.sort_unstable();
        members.dedup();
        if members.len() != votes.len() || members.len() * 3 <= n * 2 {
            return None;
        }
        let sigs: Vec<BlsSignature> = votes.iter().map(|v| v.sig).collect();
        Some(Self {
            epoch: first.epoch,
            request: first.request,
            ok: first.ok,
            machine: first.machine.clone(),
            signers: bitmap::encode(&members, n),
            sig: bls::aggregate(&sigs)?,
        })
    }

    /// dag-cbor.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("certificate encodes")
    }

    /// From dag-cbor.
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(b).ok()
    }

    /// The machine ID.
    pub fn machine_id(&self) -> [u8; 32] {
        machine32(&self.machine).unwrap_or_default()
    }

    /// Whether more than 2/3 of `panel` signed this result.
    pub fn verify(&self, chain_id: u64, panel: &[BlsPublicKey]) -> bool {
        let Some(m) = machine32(&self.machine) else { return false };
        let signers = bitmap::decode(&self.signers);
        if signers.len() * 3 <= panel.len() * 2
            || signers.iter().any(|i| *i as usize >= panel.len())
        {
            return false;
        }
        let pks: Vec<BlsPublicKey> = signers.iter().map(|i| panel[*i as usize]).collect();
        bls::fast_aggregate_verify(
            &pks,
            &attest_msg(chain_id, self.epoch, self.request, self.ok, &m),
            &self.sig,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_need_two_thirds_of_the_panel() {
        let keys: Vec<BlsSecretKey> = (0..16).map(bls::dev_key).collect();
        let panel: Vec<BlsPublicKey> = keys.iter().map(|k| k.public_key()).collect();
        let votes: Vec<AuditVote> =
            (0..11u16).map(|m| AuditVote::sign(&keys[m as usize], 7, 3, 2, true, m)).collect();
        assert!(votes.iter().all(|v| v.verify(7, &panel)));
        assert!(AuditCert::aggregate(&votes[..10], 16).is_none(), "10 of 16 is not > 2/3");
        let cert = AuditCert::aggregate(&votes, 16).unwrap();
        assert!(cert.verify(7, &panel));
        let back = AuditCert::decode(&cert.encode()).unwrap();
        assert_eq!(back, cert);
        let mut flipped = cert.clone();
        flipped.passed = false;
        assert!(!flipped.verify(7, &panel));
        assert!(!cert.verify(8, &panel), "other chain");
        let mut forged = cert.clone();
        forged.signers = bitmap::encode(&(0..11u16).map(|i| i + 5).collect::<Vec<_>>(), 16);
        assert!(!forged.verify(7, &panel));
        let v = AuditVote::decode(&votes[0].encode()).unwrap();
        assert_eq!(v, votes[0]);
    }

    #[test]
    fn verdict_certificates_are_distinct_from_audit_certificates() {
        let keys: Vec<BlsSecretKey> = (0..4).map(bls::dev_key).collect();
        let panel: Vec<BlsPublicKey> = keys.iter().map(|k| k.public_key()).collect();
        let votes: Vec<VerdictVote> =
            (0..3u16).map(|m| VerdictVote::sign(&keys[m as usize], 7, 5, 42, true, m)).collect();
        assert!(votes.iter().all(|v| v.verify(7, &panel)));
        assert!(VerdictCert::aggregate(&votes[..2], 4).is_none());
        let cert = VerdictCert::aggregate(&votes, 4).unwrap();
        assert!(cert.verify(7, &panel));
        let mut other = cert.clone();
        other.fault = false;
        assert!(!other.verify(7, &panel));
        // Same signers and numbers as an audit: the domains differ, and the encodings never
        // decode as each other.
        let audit: Vec<AuditVote> =
            (0..3u16).map(|m| AuditVote::sign(&keys[m as usize], 7, 5, 42, true, m)).collect();
        let a = AuditCert::aggregate(&audit, 4).unwrap();
        assert_ne!(a.sig, cert.sig);
        assert!(AuditCert::decode(&cert.encode()).is_none());
        assert!(VerdictCert::decode(&a.encode()).is_none());
        assert_eq!(VerdictCert::decode(&cert.encode()).unwrap(), cert);
        assert_eq!(VerdictVote::decode(&votes[1].encode()).unwrap(), votes[1]);
        let keys16: Vec<BlsSecretKey> = (0..4).map(bls::dev_key).collect();
        let panel4: Vec<BlsPublicKey> = keys16.iter().map(|k| k.public_key()).collect();
        let av: Vec<AttestVote> = (0..3u16)
            .map(|m| AttestVote::sign(&keys16[m as usize], 7, 5, 9, true, [3; 32], m))
            .collect();
        assert!(av.iter().all(|v| v.verify(7, &panel4)));
        let ac = AttestCert::aggregate(&av, 4).unwrap();
        assert!(ac.verify(7, &panel4));
        assert!(AttestCert::aggregate(&av[..2], 4).is_none());
        assert!(VerdictCert::decode(&ac.encode()).is_none());
        assert!(AuditCert::decode(&ac.encode()).is_none());
        assert!(AttestCert::decode(&cert.encode()).is_none());
        let mut other = ac.clone();
        other.machine = vec![4; 32];
        assert!(!other.verify(7, &panel4));
    }
}
