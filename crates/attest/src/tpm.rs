//! TPM 2.0 attestation for T2 machines (ADR 0013 §2.3): quotes (TPMS_ATTEST) signed by an ECC
//! P-256 attestation key (AK), the TCG crypto-agile event log replayed into the SHA-256 PCR
//! bank, the endorsement key (EK) certificate chain, and the credential challenge
//! (MakeCredential, TPM 2.0 Part 1 §24) proving the AK and the EK are in the same TPM.
//!
//! The verifier panel appraises the evidence a machine serves ([`appraise`]) and then
//! challenges it ([`make_credential`]); only the TPM holding the EK's private key can return
//! the secret. The machine ID is keccak256 of the EK's SubjectPublicKeyInfo.

use crate::{
    Error,
    der::{Point, p256_verify_raw},
};
use aes::cipher::{BlockEncrypt, KeyInit};
use alloy_primitives::{B256, keccak256};
use alloy_sol_types::SolValue;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRngCore, RngCore};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

#[allow(missing_docs)]
pub const TPM_GENERATED: u32 = 0xff54_4347;
#[allow(missing_docs)]
pub const ST_ATTEST_QUOTE: u16 = 0x8018;
#[allow(missing_docs)]
pub const ALG_SHA256: u16 = 0x000b;
#[allow(missing_docs)]
pub const ALG_ECC: u16 = 0x0023;
#[allow(missing_docs)]
pub const ALG_ECDSA: u16 = 0x0018;
#[allow(missing_docs)]
pub const ALG_NULL: u16 = 0x0010;
#[allow(missing_docs)]
pub const ECC_NIST_P256: u16 = 0x0003;

/// Object attributes an attestation key must have.
pub const AK_ATTRIBUTES: u32 = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | RESTRICTED | SIGN;
#[allow(missing_docs)]
pub const FIXED_TPM: u32 = 1 << 1;
#[allow(missing_docs)]
pub const FIXED_PARENT: u32 = 1 << 4;
#[allow(missing_docs)]
pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
#[allow(missing_docs)]
pub const USER_WITH_AUTH: u32 = 1 << 6;
#[allow(missing_docs)]
pub const RESTRICTED: u32 = 1 << 16;
#[allow(missing_docs)]
pub const DECRYPT: u32 = 1 << 17;
#[allow(missing_docs)]
pub const SIGN: u32 = 1 << 18;

/// Event types.
pub const EV_NO_ACTION: u32 = 3;
#[allow(missing_docs)]
pub const EV_IPL: u32 = 0x0d;
#[allow(missing_docs)]
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;

/// PCRs the `bolt-art` boot measures by default: firmware and its configuration (0–7) and the
/// unified kernel image (11).
pub const DEFAULT_PCRS: u32 = 0x0000_08ff;

fn tpm_err(s: impl Into<String>) -> Error {
    Error::Tpm(s.into())
}

/// Big-endian reader over TPM structures.
struct R<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let b = self.d.get(self.p..self.p + n).ok_or_else(|| tpm_err("truncated structure"))?;
        self.p += n;
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().unwrap()))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
    fn done(&self) -> bool {
        self.p == self.d.len()
    }
}

fn tpm2b(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

// ------------------------------------------------------------------ AK public area

/// An ECC P-256 signing key's public area (TPMT_PUBLIC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublic {
    /// Object attributes.
    pub attributes: u32,
    /// The public point.
    pub point: Point,
    /// The encoded TPMT_PUBLIC.
    pub raw: Vec<u8>,
}

impl EccPublic {
    /// Encodes an ECDSA-SHA256 P-256 key with `attributes`.
    pub fn new(attributes: u32, point: Point) -> Self {
        let mut b = Vec::new();
        b.extend_from_slice(&ALG_ECC.to_be_bytes());
        b.extend_from_slice(&ALG_SHA256.to_be_bytes());
        b.extend_from_slice(&attributes.to_be_bytes());
        tpm2b(&mut b, &[]); // authPolicy
        b.extend_from_slice(&ALG_NULL.to_be_bytes()); // symmetric
        b.extend_from_slice(&ALG_ECDSA.to_be_bytes()); // scheme
        b.extend_from_slice(&ALG_SHA256.to_be_bytes());
        b.extend_from_slice(&ECC_NIST_P256.to_be_bytes());
        b.extend_from_slice(&ALG_NULL.to_be_bytes()); // kdf
        tpm2b(&mut b, &point.0);
        tpm2b(&mut b, &point.1);
        Self { attributes, point, raw: b }
    }

    /// Parses a TPMT_PUBLIC; only ECC P-256 keys with an ECDSA-SHA256 scheme.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let mut r = R { d: raw, p: 0 };
        if r.u16()? != ALG_ECC {
            return Err(tpm_err("the attestation key is not an ECC key"));
        }
        if r.u16()? != ALG_SHA256 {
            return Err(tpm_err("name algorithm is not SHA-256"));
        }
        let attributes = r.u32()?;
        r.tpm2b()?;
        if r.u16()? != ALG_NULL {
            return Err(tpm_err("signing key with a symmetric algorithm"));
        }
        if r.u16()? != ALG_ECDSA || r.u16()? != ALG_SHA256 {
            return Err(tpm_err("scheme is not ECDSA-SHA256"));
        }
        if r.u16()? != ECC_NIST_P256 {
            return Err(tpm_err("curve is not P-256"));
        }
        r.u16()?; // kdf
        let x: [u8; 32] = r.tpm2b()?.try_into().map_err(|_| tpm_err("point"))?;
        let y: [u8; 32] = r.tpm2b()?.try_into().map_err(|_| tpm_err("point"))?;
        if !r.done() {
            return Err(tpm_err("trailing bytes in the public area"));
        }
        Ok(Self { attributes, point: (x, y), raw: raw.to_vec() })
    }

    /// The object's name: nameAlg ‖ SHA-256(TPMT_PUBLIC).
    pub fn name(&self) -> Vec<u8> {
        let mut n = ALG_SHA256.to_be_bytes().to_vec();
        n.extend_from_slice(&Sha256::digest(&self.raw));
        n
    }
}

// ------------------------------------------------------------------ quotes

/// A TPMS_ATTEST of type quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    /// Name of the signing key.
    pub signer: Vec<u8>,
    /// qualifyingData: the binding.
    pub extra_data: Vec<u8>,
    #[allow(missing_docs)]
    pub clock: u64,
    #[allow(missing_docs)]
    pub reset_count: u32,
    #[allow(missing_docs)]
    pub restart_count: u32,
    #[allow(missing_docs)]
    pub safe: bool,
    #[allow(missing_docs)]
    pub firmware: u64,
    /// Selected PCRs in the SHA-256 bank, as a bit mask (PCR i = bit i).
    pub pcr_mask: u32,
    /// SHA-256 over the selected PCR values in index order.
    pub pcr_digest: Vec<u8>,
}

impl Quote {
    /// Parses a TPMS_ATTEST; only quotes selecting the SHA-256 bank.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let mut r = R { d: raw, p: 0 };
        if r.u32()? != TPM_GENERATED {
            return Err(tpm_err("not generated by a TPM"));
        }
        if r.u16()? != ST_ATTEST_QUOTE {
            return Err(tpm_err("not a quote"));
        }
        let signer = r.tpm2b()?.to_vec();
        let extra_data = r.tpm2b()?.to_vec();
        let clock = r.u64()?;
        let reset_count = r.u32()?;
        let restart_count = r.u32()?;
        let safe = r.u8()? != 0;
        let firmware = r.u64()?;
        let count = r.u32()?;
        let mut mask = 0u32;
        for _ in 0..count {
            let alg = r.u16()?;
            let n = r.u8()? as usize;
            let sel = r.bytes(n)?;
            if alg != ALG_SHA256 {
                if sel.iter().any(|b| *b != 0) {
                    return Err(tpm_err("quote selects a bank other than SHA-256"));
                }
                continue;
            }
            for (i, b) in sel.iter().enumerate().take(3) {
                mask |= (*b as u32) << (8 * i);
            }
        }
        let pcr_digest = r.tpm2b()?.to_vec();
        if !r.done() {
            return Err(tpm_err("trailing bytes in the quote"));
        }
        Ok(Self {
            signer,
            extra_data,
            clock,
            reset_count,
            restart_count,
            safe,
            firmware,
            pcr_mask: mask,
            pcr_digest,
        })
    }

    /// The encoded TPMS_ATTEST.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&TPM_GENERATED.to_be_bytes());
        b.extend_from_slice(&ST_ATTEST_QUOTE.to_be_bytes());
        tpm2b(&mut b, &self.signer);
        tpm2b(&mut b, &self.extra_data);
        b.extend_from_slice(&self.clock.to_be_bytes());
        b.extend_from_slice(&self.reset_count.to_be_bytes());
        b.extend_from_slice(&self.restart_count.to_be_bytes());
        b.push(self.safe as u8);
        b.extend_from_slice(&self.firmware.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&ALG_SHA256.to_be_bytes());
        b.push(3);
        b.extend_from_slice(&self.pcr_mask.to_le_bytes()[..3]);
        tpm2b(&mut b, &self.pcr_digest);
        b
    }
}

/// Encodes an ECDSA-SHA256 TPMT_SIGNATURE.
pub fn encode_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&ALG_ECDSA.to_be_bytes());
    b.extend_from_slice(&ALG_SHA256.to_be_bytes());
    tpm2b(&mut b, r);
    tpm2b(&mut b, s);
    b
}

/// Parses an ECDSA-SHA256 TPMT_SIGNATURE into r ‖ s (64 bytes).
pub fn parse_signature(raw: &[u8]) -> Result<[u8; 64], Error> {
    let mut rd = R { d: raw, p: 0 };
    if rd.u16()? != ALG_ECDSA || rd.u16()? != ALG_SHA256 {
        return Err(tpm_err("signature is not ECDSA-SHA256"));
    }
    let mut out = [0u8; 64];
    for half in 0..2 {
        let v = rd.tpm2b()?;
        let v = if v.len() > 32 { &v[v.len() - 32..] } else { v };
        out[half * 32 + 32 - v.len()..half * 32 + 32].copy_from_slice(v);
    }
    Ok(out)
}

/// SHA-256 over the PCR values selected by `mask`, in index order (what a quote signs).
pub fn pcr_digest(pcrs: &[[u8; 32]; 24], mask: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    for (i, v) in pcrs.iter().enumerate() {
        if mask & (1 << i) != 0 {
            h.update(v);
        }
    }
    h.finalize().into()
}

/// The values `mask` selects, in index order.
pub fn selected(pcrs: &[[u8; 32]; 24], mask: u32) -> Vec<B256> {
    (0..24).filter(|i| mask & (1 << i) != 0).map(|i| B256::from(pcrs[i])).collect()
}

/// What `ImageRegistry` stores for a TPM measurement: abi.encode(uint32 mask, bytes32[] values).
pub fn measurement_bytes(mask: u32, values: &[B256]) -> Vec<u8> {
    (mask, values.to_vec()).abi_encode_params()
}

// ------------------------------------------------------------------ event log

/// One event of a TCG crypto-agile log (SHA-256 digest only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    #[allow(missing_docs)]
    pub pcr: u32,
    #[allow(missing_docs)]
    pub kind: u32,
    /// SHA-256 digest extended into the PCR.
    pub digest: [u8; 32],
    /// Event data.
    pub data: Vec<u8>,
}

/// Replays a TCG PC Client crypto-agile event log into the SHA-256 bank. Handles the Spec ID
/// header event, `StartupLocality`, and skips `EV_NO_ACTION` events.
pub fn replay(log: &[u8]) -> Result<([[u8; 32]; 24], Vec<Event>), Error> {
    let le32 = |d: &[u8], p: usize| -> Result<u32, Error> {
        Ok(u32::from_le_bytes(d.get(p..p + 4).ok_or_else(|| tpm_err("event log"))?.try_into().unwrap()))
    };
    let le16 = |d: &[u8], p: usize| -> Result<u16, Error> {
        Ok(u16::from_le_bytes(d.get(p..p + 2).ok_or_else(|| tpm_err("event log"))?.try_into().unwrap()))
    };
    // Header: TCG_PCR_EVENT (SHA-1 format) carrying the Spec ID event.
    let size = le32(log, 28)? as usize;
    let spec = log.get(32..32 + size).ok_or_else(|| tpm_err("event log header"))?;
    if !spec.starts_with(b"Spec ID Event03\0") {
        return Err(tpm_err("not a crypto-agile event log"));
    }
    let n = le32(spec, 24)? as usize;
    let mut sizes = std::collections::HashMap::new();
    for i in 0..n {
        sizes.insert(le16(spec, 28 + 4 * i)?, le16(spec, 30 + 4 * i)? as usize);
    }
    if sizes.get(&ALG_SHA256) != Some(&32) {
        return Err(tpm_err("the event log has no SHA-256 bank"));
    }
    let mut pcrs = [[0u8; 32]; 24];
    let mut events = Vec::new();
    let mut p = 32 + size;
    while p < log.len() {
        let pcr = le32(log, p)?;
        let kind = le32(log, p + 4)?;
        let count = le32(log, p + 8)?;
        let mut q = p + 12;
        let mut digest = None;
        for _ in 0..count {
            let alg = le16(log, q)?;
            let len = *sizes.get(&alg).ok_or_else(|| tpm_err("unknown digest algorithm"))?;
            if alg == ALG_SHA256 {
                digest = Some(<[u8; 32]>::try_from(&log[q + 2..q + 2 + len]).unwrap());
            }
            q += 2 + len;
        }
        let dlen = le32(log, q)? as usize;
        let data = log.get(q + 4..q + 4 + dlen).ok_or_else(|| tpm_err("event data"))?.to_vec();
        p = q + 4 + dlen;
        if pcr >= 24 {
            return Err(tpm_err("PCR index"));
        }
        if kind == EV_NO_ACTION {
            if data.starts_with(b"StartupLocality\0") && pcr == 0 {
                pcrs[0] = [0; 32];
                pcrs[0][31] = *data.get(16).unwrap_or(&0);
            }
            continue;
        }
        let digest = digest.ok_or_else(|| tpm_err("event without a SHA-256 digest"))?;
        let mut h = Sha256::new();
        h.update(pcrs[pcr as usize]);
        h.update(digest);
        pcrs[pcr as usize] = h.finalize().into();
        events.push(Event { pcr, kind, digest, data });
    }
    Ok((pcrs, events))
}

/// Encodes a crypto-agile event log (SHA-256 bank only) with the given events.
pub fn encode_log(events: &[Event]) -> Vec<u8> {
    let mut spec = b"Spec ID Event03\0".to_vec();
    spec.extend_from_slice(&0u32.to_le_bytes()); // platform class
    spec.extend_from_slice(&[0, 2, 0, 2]); // version 2.0, errata 0, uintn 2 (8 bytes)
    spec.extend_from_slice(&1u32.to_le_bytes());
    spec.extend_from_slice(&ALG_SHA256.to_le_bytes());
    spec.extend_from_slice(&32u16.to_le_bytes());
    spec.push(0); // vendor info
    let mut b = Vec::new();
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]);
    b.extend_from_slice(&(spec.len() as u32).to_le_bytes());
    b.extend_from_slice(&spec);
    for e in events {
        b.extend_from_slice(&e.pcr.to_le_bytes());
        b.extend_from_slice(&e.kind.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&ALG_SHA256.to_le_bytes());
        b.extend_from_slice(&e.digest);
        b.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        b.extend_from_slice(&e.data);
    }
    b
}

// ------------------------------------------------------------------ evidence and appraisal

mod hexser {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

mod hexvec {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut q = s.serialize_seq(Some(v.len()))?;
        for x in v {
            q.serialize_element(&hex::encode(x))?;
        }
        q.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.iter().map(|s| hex::decode(s).map_err(serde::de::Error::custom)).collect()
    }
}

/// What a T2 machine serves for appraisal (its sha256 is what goes on chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// EK certificate (DER).
    #[serde(with = "hexser")]
    pub ek_cert: Vec<u8>,
    /// Intermediate certificates up to a vendor root (DER).
    #[serde(with = "hexvec", default)]
    pub ek_chain: Vec<Vec<u8>>,
    /// The AK's TPMT_PUBLIC.
    #[serde(with = "hexser")]
    pub ak_public: Vec<u8>,
    /// TPMS_ATTEST.
    #[serde(with = "hexser")]
    pub quote: Vec<u8>,
    /// TPMT_SIGNATURE over the quote.
    #[serde(with = "hexser")]
    pub signature: Vec<u8>,
    /// TCG crypto-agile event log.
    #[serde(with = "hexser")]
    pub event_log: Vec<u8>,
}

impl Evidence {
    /// Canonical encoding (JSON).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("evidence JSON")
    }

    /// Parses the canonical encoding.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(b).map_err(|e| tpm_err(format!("evidence: {e}")))
    }

    /// sha256 of the canonical encoding: what `EnclaveLease` records.
    pub fn digest(&self) -> B256 {
        B256::from(<[u8; 32]>::from(Sha256::digest(self.to_bytes())))
    }
}

/// The result of appraising evidence.
#[derive(Debug, Clone)]
pub struct Appraisal {
    /// keccak256 of the EK's SubjectPublicKeyInfo.
    pub machine_id: B256,
    /// The AK's name (for the credential challenge).
    pub ak_name: Vec<u8>,
    /// The quote's qualifyingData.
    pub qualifying_data: Vec<u8>,
    /// Selected PCRs.
    pub pcr_mask: u32,
    /// Their replayed values, in index order.
    pub pcrs: Vec<B256>,
    /// keccak256(abi.encode(mask, values)): the measurement images register.
    pub measurement: B256,
    /// The EK public key (SubjectPublicKeyInfo DER).
    pub ek_spki: Vec<u8>,
}

/// Verifies evidence: the EK certificate chains to one of `roots` (DER) and is valid at
/// `now`; the AK is a restricted, TPM-bound P-256 signing key; the quote is signed by it and
/// its PCR digest matches the replayed event log. Proving the AK is in the EK's TPM is the
/// separate credential challenge.
pub fn appraise(ev: &Evidence, roots: &[Vec<u8>], now: u64) -> Result<Appraisal, Error> {
    // EK certificate chain.
    let (_, ek) = X509Certificate::from_der(&ev.ek_cert).map_err(|_| tpm_err("EK certificate"))?;
    let mut chain = Vec::new();
    for c in &ev.ek_chain {
        chain.push(X509Certificate::from_der(c).map_err(|_| tpm_err("EK chain"))?.1);
    }
    let mut anchors = Vec::new();
    for c in roots {
        anchors.push(X509Certificate::from_der(c).map_err(|_| tpm_err("TPM root"))?.1);
    }
    let in_time = |c: &X509Certificate<'_>| {
        let v = c.validity();
        (v.not_before.timestamp() as u64) <= now && now <= v.not_after.timestamp() as u64
    };
    let mut cur = &ek;
    let mut i = 0;
    loop {
        if !in_time(cur) {
            return Err(tpm_err("EK certificate chain out of its validity"));
        }
        if let Some(root) = anchors.iter().find(|r| r.subject().as_raw() == cur.issuer().as_raw())
            && cur.verify_signature(Some(root.public_key())).is_ok()
        {
            break;
        }
        let Some(next) = chain.get(i) else {
            return Err(tpm_err("EK certificate does not chain to a trusted TPM vendor"));
        };
        if next.subject().as_raw() != cur.issuer().as_raw()
            || cur.verify_signature(Some(next.public_key())).is_err()
        {
            return Err(tpm_err("EK certificate chain signature"));
        }
        cur = next;
        i += 1;
    }
    let ek_spki = ek.public_key().raw.to_vec();

    // Attestation key and quote.
    let ak = EccPublic::parse(&ev.ak_public)?;
    if ak.attributes & AK_ATTRIBUTES != AK_ATTRIBUTES || ak.attributes & DECRYPT != 0 {
        return Err(tpm_err("the attestation key is not a restricted TPM-bound signing key"));
    }
    let sig = parse_signature(&ev.signature)?;
    if !p256_verify_raw(&ev.quote, &sig, &ak.point) {
        return Err(tpm_err("quote signature"));
    }
    let q = Quote::parse(&ev.quote)?;
    if q.signer != ak.name() {
        return Err(tpm_err("quote signed by another key"));
    }
    let (pcrs, _) = replay(&ev.event_log)?;
    if q.pcr_digest != pcr_digest(&pcrs, q.pcr_mask) {
        return Err(tpm_err("PCR digest does not match the event log"));
    }
    let values = selected(&pcrs, q.pcr_mask);
    Ok(Appraisal {
        machine_id: keccak256(&ek_spki),
        ak_name: ak.name(),
        qualifying_data: q.extra_data,
        pcr_mask: q.pcr_mask,
        measurement: keccak256(measurement_bytes(q.pcr_mask, &values)),
        pcrs: values,
        ek_spki,
    })
}

/// The qualifyingData a T2 activation quote carries: keccak256(binding ‖ agentHash).
pub fn activation_data(binding: B256, agent_hash: B256) -> B256 {
    keccak256([binding.as_slice(), agent_hash.as_slice()].concat())
}

// ------------------------------------------------------------------ credential challenge

/// KDFa (TPM 2.0 Part 1 §11.4.10.2) with HMAC-SHA256.
pub fn kdfa(key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::new();
    let mut counter = 1u32;
    while out.len() < bytes {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac");
        m.update(&counter.to_be_bytes());
        m.update(label.as_bytes());
        m.update(&[0]);
        m.update(context_u);
        m.update(context_v);
        m.update(&bits.to_be_bytes());
        out.extend_from_slice(&m.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(bytes);
    out
}

/// AES-128 in CFB mode with a zero IV (TPM parameter/credential encryption); `decrypt` selects
/// the direction.
pub fn aes_cfb(key: &[u8], data: &[u8], decrypt: bool) -> Vec<u8> {
    let c = aes::Aes128::new_from_slice(key).expect("AES-128 key");
    let mut iv = [0u8; 16];
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = aes::Block::from(iv);
        c.encrypt_block(&mut ks);
        let o: Vec<u8> = chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        let fb = if decrypt { chunk } else { &o[..] };
        iv[..fb.len()].copy_from_slice(fb);
        out.extend_from_slice(&o);
    }
    out
}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().to_vec()
}

/// A credential challenge for the TPM whose EK is `ek_spki` (RSA-2048) and the AK named
/// `ak_name`: returns (TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET). Only that TPM can recover
/// `secret` with ActivateCredential.
pub fn make_credential(
    ek_spki: &[u8],
    ak_name: &[u8],
    secret: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let ek = RsaPublicKey::from_public_key_der(ek_spki)
        .map_err(|_| tpm_err("only RSA endorsement keys are supported"))?;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let enc_seed = ek
        .encrypt(rng, Oaep::new_with_label::<Sha256, _>("IDENTITY\0"), &seed)
        .map_err(|e| tpm_err(format!("OAEP: {e}")))?;
    let sym = kdfa(&seed, "STORAGE", ak_name, &[], 128);
    let mut plain = Vec::new();
    tpm2b(&mut plain, secret);
    let enc_identity = aes_cfb(&sym, &plain, false);
    let hmac_key = kdfa(&seed, "INTEGRITY", &[], &[], 256);
    let integrity = hmac256(&hmac_key, &[&enc_identity, ak_name]);
    let mut inner = Vec::new();
    tpm2b(&mut inner, &integrity);
    inner.extend_from_slice(&enc_identity);
    let mut blob = Vec::new();
    tpm2b(&mut blob, &inner);
    let mut enc = Vec::new();
    tpm2b(&mut enc, &enc_seed);
    Ok((blob, enc))
}

/// The second half of ActivateCredential once the TPM has decrypted the seed: checks the
/// integrity HMAC and returns the secret.
pub fn open_credential(seed: &[u8], ak_name: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = R { d: blob, p: 0 };
    let inner = r.tpm2b()?;
    let mut r = R { d: inner, p: 0 };
    let integrity = r.tpm2b()?;
    let enc_identity = &inner[r.p..];
    let hmac_key = kdfa(seed, "INTEGRITY", &[], &[], 256);
    if hmac256(&hmac_key, &[enc_identity, ak_name]) != integrity {
        return Err(tpm_err("credential integrity"));
    }
    let sym = kdfa(seed, "STORAGE", ak_name, &[], 128);
    let plain = aes_cfb(&sym, enc_identity, true);
    let mut r = R { d: &plain, p: 0 };
    Ok(r.tpm2b()?.to_vec())
}

/// A random 32-byte challenge secret.
pub fn challenge_secret(rng: &mut impl RngCore) -> [u8; 32] {
    let mut s = [0u8; 32];
    rng.fill_bytes(&mut s);
    s
}
