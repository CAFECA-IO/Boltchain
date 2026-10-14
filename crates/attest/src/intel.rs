//! Intel attestation collateral, evaluated exactly as `TeeCollateral` does on chain: CAs under
//! the root, CRLs, TDX TCB info (v3) and the TD quoting enclave identity.

use crate::{
    Error,
    der::{Cert, Crl, Point, expect, int32, p256_verify_raw, tlv},
};
use alloy_primitives::B256;
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Intel SGX Root CA public key.
pub const INTEL_ROOT: Point = (
    hex_literal(b"0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5"),
    hex_literal(b"67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394"),
);

const fn hex_literal(h: &[u8; 64]) -> [u8; 32] {
    const fn v(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex"),
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = v(h[2 * i]) << 4 | v(h[2 * i + 1]);
        i += 1;
    }
    out
}

/// TCB statuses (`TeeCollateral` numbering; larger is worse).
pub mod status {
    /// Not found in the collateral.
    pub const UNKNOWN: u8 = 0;
    #[allow(missing_docs)]
    pub const UP_TO_DATE: u8 = 1;
    #[allow(missing_docs)]
    pub const SW_HARDENING_NEEDED: u8 = 2;
    #[allow(missing_docs)]
    pub const CONFIGURATION_NEEDED: u8 = 3;
    #[allow(missing_docs)]
    pub const CONFIGURATION_AND_SW_HARDENING_NEEDED: u8 = 4;
    #[allow(missing_docs)]
    pub const OUT_OF_DATE: u8 = 5;
    #[allow(missing_docs)]
    pub const OUT_OF_DATE_CONFIGURATION_NEEDED: u8 = 6;
    #[allow(missing_docs)]
    pub const REVOKED: u8 = 7;

    /// Intel's name for a status.
    pub fn name(s: u8) -> &'static str {
        match s {
            1 => "UpToDate",
            2 => "SWHardeningNeeded",
            3 => "ConfigurationNeeded",
            4 => "ConfigurationAndSWHardeningNeeded",
            5 => "OutOfDate",
            6 => "OutOfDateConfigurationNeeded",
            7 => "Revoked",
            _ => "Unknown",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<u8> {
        (1..=7).find(|&i| name(i) == s)
    }
}

/// A certificate authority under the root.
#[derive(Debug, Clone, Copy)]
pub struct Ca {
    /// Public key.
    pub key: Point,
    /// Unix seconds.
    pub not_after: u64,
}

#[derive(Debug, Clone)]
struct TcbLevel {
    sgx: [u8; 16],
    pcesvn: u16,
    tdx: [u8; 16],
    status: u8,
}

#[derive(Debug, Clone)]
struct Module {
    mrsigner: Vec<u8>,
    attributes: [u8; 8],
    mask: [u8; 8],
    levels: Vec<(u8, u8)>, // (isvsvn, status), descending
}

/// TDX TCB info for one FMSPC.
#[derive(Debug, Clone)]
pub struct TcbInfo {
    /// `tcbEvaluationDataNumber`.
    pub evaluation: u32,
    /// Unix seconds.
    pub issue_date: u64,
    /// Unix seconds.
    pub next_update: u64,
    seam_mrsigner: Vec<u8>,
    seam_attributes: [u8; 8],
    seam_mask: [u8; 8],
    levels: Vec<TcbLevel>,
    modules: HashMap<u8, Module>,
}

/// The TD quoting enclave identity.
#[derive(Debug, Clone)]
pub struct QeIdentity {
    /// `tcbEvaluationDataNumber`.
    pub evaluation: u32,
    /// Unix seconds.
    pub issue_date: u64,
    /// Unix seconds.
    pub next_update: u64,
    miscselect: [u8; 4],
    miscselect_mask: [u8; 4],
    attributes: [u8; 16],
    attributes_mask: [u8; 16],
    mrsigner: [u8; 32],
    isvprodid: u16,
    levels: Vec<(u16, u8)>,
}

/// Collateral as accepted so far.
#[derive(Debug, Clone)]
pub struct Collateral {
    root: Point,
    cas: HashMap<B256, Ca>,
    revoked: HashSet<(B256, B256)>,
    crl_this_update: HashMap<B256, u64>,
    tcb: HashMap<[u8; 6], TcbInfo>,
    qe: Option<QeIdentity>,
}

#[derive(Deserialize)]
struct Signed<'a> {
    #[serde(borrow, rename = "tcbInfo")]
    tcb_info: Option<&'a RawValue>,
    #[serde(borrow, rename = "enclaveIdentity")]
    enclave_identity: Option<&'a RawValue>,
    signature: String,
}

fn hexn<const N: usize>(v: &Value) -> Result<[u8; N], Error> {
    let s = v.as_str().ok_or(Error::Collateral("expected a hex string"))?;
    let b = hex::decode(s).map_err(|_| Error::Collateral("hex"))?;
    b.try_into().map_err(|_| Error::Collateral("hex length"))
}

fn uint(v: &Value) -> Result<u64, Error> {
    v.as_u64().ok_or(Error::Collateral("expected a number"))
}

/// An ISO 8601 date (`2026-10-13T08:53:03Z`) in Unix seconds.
pub fn date(v: &Value) -> Result<u64, Error> {
    let s = v.as_str().ok_or(Error::Collateral("expected a date"))?;
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| Error::Collateral("date"))?;
    Ok(t.unix_timestamp() as u64)
}

fn svns(v: &Value) -> Result<[u8; 16], Error> {
    let a = v.as_array().ok_or(Error::Collateral("components"))?;
    if a.len() != 16 {
        return Err(Error::Collateral("components"));
    }
    let mut out = [0u8; 16];
    for (i, c) in a.iter().enumerate() {
        out[i] = uint(&c["svn"])? as u8;
    }
    Ok(out)
}

fn st(v: &Value) -> Result<u8, Error> {
    status::parse(v.as_str().unwrap_or("")).ok_or(Error::Collateral("status"))
}

impl Collateral {
    /// Empty collateral under the Intel SGX Root CA.
    pub fn intel() -> Self {
        Self::with_root(INTEL_ROOT)
    }

    /// Empty collateral under `root` (simulated PKIs).
    pub fn with_root(root: Point) -> Self {
        Self {
            root,
            cas: HashMap::new(),
            revoked: HashSet::new(),
            crl_this_update: HashMap::new(),
            tcb: HashMap::new(),
            qe: None,
        }
    }

    /// The trust anchor.
    pub fn root(&self) -> Point {
        self.root
    }

    /// A CA certificate signed by the root (as `addCa`).
    pub fn add_ca(&mut self, der: &[u8], now: u64) -> Result<B256, Error> {
        let c = Cert::parse(der)?;
        if !c.signed_by(&self.root) {
            return Err(Error::Signature("CA certificate"));
        }
        if !c.valid_at(now) {
            return Err(Error::Expired("CA certificate"));
        }
        if self.revoked.contains(&(c.issuer, c.serial)) {
            return Err(Error::Revoked);
        }
        self.cas.insert(c.subject, Ca { key: c.key, not_after: c.not_after });
        Ok(c.subject)
    }

    /// A CRL from the root or a known CA (as `setCrl`).
    pub fn add_crl(&mut self, der: &[u8]) -> Result<(), Error> {
        let l = Crl::parse(der)?;
        let key = self.cas.get(&l.issuer).map(|c| c.key).unwrap_or(self.root);
        if !l.signed_by(&key) {
            return Err(Error::Signature("CRL"));
        }
        if l.this_update <= self.crl_this_update.get(&l.issuer).copied().unwrap_or(0) {
            return Err(Error::Collateral("CRL not newer"));
        }
        self.crl_this_update.insert(l.issuer, l.this_update);
        for s in l.serials {
            self.revoked.insert((l.issuer, s));
        }
        Ok(())
    }

    /// The CA with subject hash `subject`.
    pub fn ca(&self, subject: &B256) -> Option<Ca> {
        self.cas.get(subject).copied()
    }

    /// Whether `serial` of `issuer` is revoked.
    pub fn is_revoked(&self, issuer: &B256, serial: &B256) -> bool {
        self.revoked.contains(&(*issuer, *serial))
    }

    fn check_signed(&self, body: &RawValue, sig: &str, now: u64) -> Result<B256, Error> {
        let sig = hex::decode(sig).map_err(|_| Error::Collateral("signature hex"))?;
        for (subject, ca) in &self.cas {
            if p256_verify_raw(body.get().as_bytes(), &sig, &ca.key) {
                if now > ca.not_after {
                    return Err(Error::Expired("collateral signer"));
                }
                return Ok(*subject);
            }
        }
        Err(Error::Signature("collateral"))
    }

    /// TDX TCB info v3 (`{"tcbInfo":…,"signature":…}`); returns the FMSPC and the signer.
    pub fn set_tcb_info(&mut self, json: &str, now: u64) -> Result<([u8; 6], B256), Error> {
        let doc: Signed<'_> = serde_json::from_str(json).map_err(|_| Error::Collateral("JSON"))?;
        let raw = doc.tcb_info.ok_or(Error::Collateral("tcbInfo"))?;
        let signer = self.check_signed(raw, &doc.signature, now)?;
        let i: Value = serde_json::from_str(raw.get()).map_err(|_| Error::Collateral("JSON"))?;
        if i["id"] != "TDX" || i["version"] != 3 {
            return Err(Error::Collateral("not TDX TCB info v3"));
        }
        let fmspc: [u8; 6] = hexn(&i["fmspc"])?;
        let evaluation = uint(&i["tcbEvaluationDataNumber"])? as u32;
        let issue_date = date(&i["issueDate"])?;
        if let Some(cur) = self.tcb.get(&fmspc)
            && (evaluation < cur.evaluation
                || (evaluation == cur.evaluation && issue_date <= cur.issue_date))
        {
            return Err(Error::Collateral("TCB info not newer"));
        }
        let m = &i["tdxModule"];
        let mut levels = Vec::new();
        for l in i["tcbLevels"].as_array().ok_or(Error::Collateral("tcbLevels"))? {
            let t = &l["tcb"];
            levels.push(TcbLevel {
                sgx: svns(&t["sgxtcbcomponents"])?,
                pcesvn: uint(&t["pcesvn"])? as u16,
                tdx: svns(&t["tdxtcbcomponents"])?,
                status: st(&l["tcbStatus"])?,
            });
        }
        let mut modules = HashMap::new();
        if let Some(ids) = i["tdxModuleIdentities"].as_array() {
            for e in ids {
                let id = e["id"].as_str().unwrap_or("");
                let major = id
                    .strip_prefix("TDX_")
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or(Error::Collateral("module id"))?;
                let mut lv = Vec::new();
                for l in e["tcbLevels"].as_array().ok_or(Error::Collateral("tcbLevels"))? {
                    lv.push((uint(&l["tcb"]["isvsvn"])? as u8, st(&l["tcbStatus"])?));
                }
                modules.insert(
                    major,
                    Module {
                        mrsigner: hex::decode(e["mrsigner"].as_str().unwrap_or(""))
                            .map_err(|_| Error::Collateral("hex"))?,
                        attributes: hexn(&e["attributes"])?,
                        mask: hexn(&e["attributesMask"])?,
                        levels: lv,
                    },
                );
            }
        }
        self.tcb.insert(
            fmspc,
            TcbInfo {
                evaluation,
                issue_date,
                next_update: date(&i["nextUpdate"])?,
                seam_mrsigner: hex::decode(m["mrsigner"].as_str().unwrap_or(""))
                    .map_err(|_| Error::Collateral("hex"))?,
                seam_attributes: hexn(&m["attributes"])?,
                seam_mask: hexn(&m["attributesMask"])?,
                levels,
                modules,
            },
        );
        Ok((fmspc, signer))
    }

    /// The TD quoting enclave identity; returns the signer.
    pub fn set_qe_identity(&mut self, json: &str, now: u64) -> Result<B256, Error> {
        let doc: Signed<'_> = serde_json::from_str(json).map_err(|_| Error::Collateral("JSON"))?;
        let raw = doc.enclave_identity.ok_or(Error::Collateral("enclaveIdentity"))?;
        let signer = self.check_signed(raw, &doc.signature, now)?;
        let e: Value = serde_json::from_str(raw.get()).map_err(|_| Error::Collateral("JSON"))?;
        if e["id"] != "TD_QE" {
            return Err(Error::Collateral("not the TD_QE identity"));
        }
        let evaluation = uint(&e["tcbEvaluationDataNumber"])? as u32;
        let issue_date = date(&e["issueDate"])?;
        if let Some(cur) = &self.qe
            && (evaluation < cur.evaluation
                || (evaluation == cur.evaluation && issue_date <= cur.issue_date))
        {
            return Err(Error::Collateral("QE identity not newer"));
        }
        let mut levels = Vec::new();
        for l in e["tcbLevels"].as_array().ok_or(Error::Collateral("tcbLevels"))? {
            levels.push((uint(&l["tcb"]["isvsvn"])? as u16, st(&l["tcbStatus"])?));
        }
        self.qe = Some(QeIdentity {
            evaluation,
            issue_date,
            next_update: date(&e["nextUpdate"])?,
            miscselect: hexn(&e["miscselect"])?,
            miscselect_mask: hexn(&e["miscselectMask"])?,
            attributes: hexn(&e["attributes"])?,
            attributes_mask: hexn(&e["attributesMask"])?,
            mrsigner: hexn(&e["mrsigner"])?,
            isvprodid: uint(&e["isvprodid"])? as u16,
            levels,
        });
        Ok(signer)
    }

    /// TCB info for `fmspc`.
    pub fn tcb_info(&self, fmspc: &[u8; 6]) -> Option<&TcbInfo> {
        self.tcb.get(fmspc)
    }

    /// The QE identity.
    pub fn qe_identity(&self) -> Option<&QeIdentity> {
        self.qe.as_ref()
    }

    /// TCB status of a TDX platform and the TCB info's `nextUpdate` (as `tdxStatus`).
    pub fn tdx_status(
        &self,
        fmspc: &[u8; 6],
        comp_svn: &[u8; 16],
        pcesvn: u16,
        tee_tcb_svn: &[u8; 16],
        mr_signer_seam: &[u8],
        seam_attributes: &[u8; 8],
    ) -> (u8, u64) {
        let Some(info) = self.tcb.get(fmspc) else { return (status::UNKNOWN, 0) };
        let next = info.next_update;
        let masked = |a: &[u8; 8], m: &[u8; 8]| -> [u8; 8] { std::array::from_fn(|i| a[i] & m[i]) };
        let major = tee_tcb_svn[1];
        let mut module_status = status::UP_TO_DATE;
        if major == 0 {
            if mr_signer_seam != info.seam_mrsigner.as_slice()
                || masked(seam_attributes, &info.seam_mask) != info.seam_attributes
            {
                return (status::UNKNOWN, next);
            }
        } else {
            let Some(mi) = info.modules.get(&major) else { return (status::UNKNOWN, next) };
            if mr_signer_seam != mi.mrsigner.as_slice()
                || masked(seam_attributes, &mi.mask) != mi.attributes
            {
                return (status::UNKNOWN, next);
            }
            match mi.levels.iter().find(|(svn, _)| tee_tcb_svn[0] >= *svn) {
                Some((_, s)) => module_status = *s,
                None => return (status::UNKNOWN, next),
            }
        }
        let from = if major == 0 { 0 } else { 2 };
        for l in &info.levels {
            if pcesvn < l.pcesvn {
                continue;
            }
            if (0..16).all(|k| comp_svn[k] >= l.sgx[k])
                && (from..16).all(|k| tee_tcb_svn[k] >= l.tdx[k])
            {
                return (l.status.max(module_status), next);
            }
        }
        (status::UNKNOWN, next)
    }

    /// Status of a TD quoting enclave (as `qeStatus`).
    pub fn qe_status(
        &self,
        miscselect: &[u8; 4],
        attributes: &[u8; 16],
        mrsigner: &[u8; 32],
        isvprodid: u16,
        isvsvn: u16,
    ) -> (u8, u64) {
        let Some(qe) = &self.qe else { return (status::UNKNOWN, 0) };
        let ms: [u8; 4] = std::array::from_fn(|i| miscselect[i] & qe.miscselect_mask[i]);
        let at: [u8; 16] = std::array::from_fn(|i| attributes[i] & qe.attributes_mask[i]);
        if ms != qe.miscselect || at != qe.attributes || *mrsigner != qe.mrsigner || isvprodid != qe.isvprodid
        {
            return (status::UNKNOWN, qe.next_update);
        }
        match qe.levels.iter().find(|(svn, _)| isvsvn >= *svn) {
            Some((_, s)) => (*s, qe.next_update),
            None => (status::UNKNOWN, qe.next_update),
        }
    }
}

/// The SGX extension of a PCK certificate (OID 1.2.840.113741.1.13.1).
#[derive(Debug, Clone, Default)]
pub struct PckExtension {
    /// Platform provisioning ID.
    pub ppid: [u8; 16],
    #[allow(missing_docs)]
    pub cpusvn: [u8; 16],
    #[allow(missing_docs)]
    pub pcesvn: u16,
    #[allow(missing_docs)]
    pub pceid: [u8; 2],
    #[allow(missing_docs)]
    pub fmspc: [u8; 6],
    /// SGX TCB component SVNs.
    pub comp_svn: [u8; 16],
}

/// The SGX extension OID.
pub const SGX_OID: &str = "1.2.840.113741.1.13.1";
const SGX_OID_DER: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01];

impl PckExtension {
    /// Parses the extension of `cert`.
    pub fn of(cert: &Cert) -> Result<Self, Error> {
        let d = cert.extension(SGX_OID).ok_or(Error::Der("no SGX extension"))?;
        let mut x = Self::default();
        let (seq, len) = expect(d, 0, 0x30)?;
        let mut p = seq;
        let mut found = 0;
        while p < seq + len {
            let (e, elen) = expect(d, p, 0x30)?;
            let (o, olen) = expect(d, e, 0x06)?;
            p = e + elen;
            if olen != 10 || d[o..o + 9] != SGX_OID_DER {
                continue;
            }
            let val = o + olen;
            let octets = |n: usize| -> Result<&[u8], Error> {
                let (s, l) = expect(d, val, 0x04)?;
                if l != n {
                    return Err(Error::Der("SGX extension length"));
                }
                Ok(&d[s..s + l])
            };
            match d[o + 9] {
                1 => {
                    x.ppid.copy_from_slice(octets(16)?);
                    found |= 1;
                }
                2 => {
                    let (s, l) = expect(d, val, 0x30)?;
                    let mut q = s;
                    while q < s + l {
                        let (e2, l2) = expect(d, q, 0x30)?;
                        q = e2 + l2;
                        let (o2, ol2) = expect(d, e2, 0x06)?;
                        if ol2 != 11 {
                            continue;
                        }
                        let arc = d[o2 + 10];
                        let v = o2 + ol2;
                        match arc {
                            1..=16 => {
                                let (is, il) = expect(d, v, 0x02)?;
                                x.comp_svn[arc as usize - 1] = int32(&d[is..is + il])?[31];
                            }
                            17 => {
                                let (is, il) = expect(d, v, 0x02)?;
                                let n = int32(&d[is..is + il])?;
                                x.pcesvn = u16::from_be_bytes([n[30], n[31]]);
                            }
                            18 => {
                                let (cs, cl) = expect(d, v, 0x04)?;
                                if cl != 16 {
                                    return Err(Error::Der("cpusvn"));
                                }
                                x.cpusvn.copy_from_slice(&d[cs..cs + cl]);
                            }
                            _ => {}
                        }
                    }
                    found |= 2;
                }
                3 => {
                    x.pceid.copy_from_slice(octets(2)?);
                    found |= 4;
                }
                4 => {
                    x.fmspc.copy_from_slice(octets(6)?);
                    found |= 8;
                }
                _ => {}
            }
        }
        let _ = tlv;
        if found != 15 {
            return Err(Error::Der("incomplete SGX extension"));
        }
        Ok(x)
    }
}

/// sha256 helper.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
