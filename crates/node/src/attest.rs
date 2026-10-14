//! Verifier-panel duty for TEE attestations (ADR 0013 §6.4): a T2 machine's registration or a
//! lease activation waits in `EnclaveLease` until the panel of its epoch appraises the evidence
//! the machine serves, challenges its TPM, and certifies the result with BLS signatures.
//!
//! The machine's endpoint serves `GET /attest/evidence/<sha256 hex>` (the evidence bundle the
//! request names) and `POST /attest/challenge` (`{"blob","secret"}` hex → `{"credential"}`:
//! TPM2_ActivateCredential). Plain HTTP is enough: the evidence is checked against its hash on
//! chain and the challenge can only be answered by the TPM holding the EK.

use crate::wallet::http;
use alloy_primitives::{Address, B256, U256, hex};
use anyhow::Result;
use bolt_attest::tpm::{self, Evidence};
use bolt_system::{abi::*, addresses::*};
use std::time::Duration;

/// Request kinds (`EnclaveLease`).
pub const REQ_MACHINE: u8 = 1;
#[allow(missing_docs)]
pub const REQ_ACTIVATE: u8 = 2;

/// How long a member waits for a machine's endpoint.
pub const ENDPOINT_TIMEOUT: Duration = Duration::from_secs(20);

/// What a verifier reads from the chain for one request.
#[derive(Clone)]
pub struct Pending {
    /// Request id.
    pub id: u64,
    /// The request.
    pub request: IEnclaveLease::Request,
    /// The machine it concerns.
    pub machine: IEnclaveLease::Machine,
    /// The qualifying data its quote must carry.
    pub expect: B256,
    /// For activations: the lease's image (whose TPM measurements are allowed).
    pub image: Option<u64>,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending").field("id", &self.id).field("expect", &self.expect).finish()
    }
}

/// Reads request `id` and what its evidence must show; `None` if it is not waiting for a panel.
pub fn pending<F>(id: u64, view: F) -> Result<Option<Pending>>
where
    F: Fn(Address, Vec<u8>) -> Result<Vec<u8>>,
{
    use alloy_sol_types::SolCall;
    let call = |to: Address, c: Vec<u8>| view(to, c);
    let req = IEnclaveLease::requestCall::abi_decode_returns(
        &call(LEASES, IEnclaveLease::requestCall { r: U256::from(id) }.abi_encode())?,
    )?;
    if req.state != 1 || req.epoch == 0 {
        return Ok(None);
    }
    let machine = IEnclaveLease::machineCall::abi_decode_returns(
        &call(LEASES, IEnclaveLease::machineCall { m: req.machine }.abi_encode())?,
    )?;
    let (expect, image) = if req.kind == REQ_MACHINE {
        let b = IEnclaveLease::machineBindingCall::abi_decode_returns(&call(
            LEASES,
            IEnclaveLease::machineBindingCall { operator: machine.operator }.abi_encode(),
        )?)?;
        (b, None)
    } else {
        let lease = IEnclaveLease::leaseCall::abi_decode_returns(
            &call(LEASES, IEnclaveLease::leaseCall { id: req.lease }.abi_encode())?,
        )?;
        let b = IEnclaveLease::enclaveBindingCall::abi_decode_returns(&call(
            LEASES,
            IEnclaveLease::enclaveBindingCall { id: req.lease, signer: req.signer, encKey: req.encKey }
                .abi_encode(),
        )?)?;
        (tpm::activation_data(b, lease.agentHash), Some(lease.image))
    };
    Ok(Some(Pending { id, request: req, machine, expect, image }))
}

/// The panel's answer for one request: `Some((accepted, machine ID))`, or `None` to abstain
/// (endpoint unreachable, no trusted TPM roots configured): the member tries again later.
pub fn appraise<A>(p: &Pending, roots: &[Vec<u8>], now: u64, allows: A) -> Option<(bool, B256)>
where
    A: Fn(u64, B256) -> Result<bool>,
{
    let refuse = |why: &str| {
        tracing::info!(request = p.id, "attestation refused: {why}");
        Some((false, B256::ZERO))
    };
    if roots.is_empty() {
        tracing::debug!(request = p.id, "no trusted TPM roots: abstaining");
        return None;
    }
    let base = p.machine.endpoint.trim_end_matches('/');
    let url = format!("{base}/attest/evidence/{}", hex::encode(p.request.evidence));
    let bytes = match http("GET", &url, None, ENDPOINT_TIMEOUT) {
        Ok((200, b)) => b,
        Ok((code, _)) => {
            tracing::debug!(request = p.id, code, "evidence not served");
            return None;
        }
        Err(e) => {
            tracing::debug!(request = p.id, "evidence: {e:#}");
            return None;
        }
    };
    let digest = B256::from(<[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&bytes)));
    if digest != p.request.evidence {
        return refuse("evidence does not match its hash");
    }
    let ev = match Evidence::from_bytes(&bytes) {
        Ok(e) => e,
        Err(e) => return refuse(&e.to_string()),
    };
    let a = match tpm::appraise(&ev, roots, now) {
        Ok(a) => a,
        Err(e) => return refuse(&e.to_string()),
    };
    if a.qualifying_data != p.expect.as_slice() {
        return refuse("quote bound to something else");
    }
    if p.request.kind == REQ_ACTIVATE {
        if a.machine_id != p.machine.machineId {
            return refuse("another machine");
        }
        match allows(p.image.unwrap_or(0), a.measurement) {
            Ok(true) => {}
            Ok(false) => return refuse("measurement not registered for the image"),
            Err(_) => return None,
        }
    }
    // The AK must be in the TPM holding the EK: only it can open the credential.
    let mut rng = rand_core::OsRng;
    let secret = tpm::challenge_secret(&mut rng);
    let (blob, enc) = match tpm::make_credential(&a.ek_spki, &a.ak_name, &secret, &mut rng) {
        Ok(c) => c,
        Err(e) => return refuse(&e.to_string()),
    };
    let body = serde_json::json!({"blob": hex::encode(blob), "secret": hex::encode(enc)}).to_string();
    let url = format!("{base}/attest/challenge");
    let answer = match http("POST", &url, Some(body.as_bytes()), ENDPOINT_TIMEOUT) {
        Ok((200, b)) => b,
        Ok(_) | Err(_) => return None,
    };
    let got = serde_json::from_slice::<serde_json::Value>(&answer)
        .ok()
        .and_then(|v| v["credential"].as_str().and_then(|h| hex::decode(h).ok()));
    if got.as_deref() != Some(&secret[..]) {
        return refuse("credential challenge failed");
    }
    Some((true, a.machine_id))
}

/// TPM vendor roots a verifier trusts: those in `dir` (DER or PEM files), plus the simulated
/// vendor on development chains.
pub fn tpm_roots(dir: Option<&std::path::Path>, dev: bool) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if let Some(d) = dir {
        for e in std::fs::read_dir(d)? {
            let b = std::fs::read(e?.path())?;
            if b.starts_with(b"-----BEGIN") {
                out.extend(bolt_attest::der::pem_certs(&b)?);
            } else {
                out.push(b);
            }
        }
    }
    if dev {
        out.push(bolt_attest::tpm_sim::SimTpmCa::dev().root_der());
    }
    Ok(out)
}
