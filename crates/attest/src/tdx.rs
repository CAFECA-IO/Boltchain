//! Intel TDX quotes (DCAP v4, ECDSA-256 attestation key): layout and verification, the same
//! steps as `TdxVerifier` on chain.

use crate::{
    Error,
    der::{Cert, Point, p256_verify_raw, pem_certs},
    intel::{Collateral, PckExtension, sha256, status},
};
use alloy_primitives::{B256, keccak256};

/// Header length.
pub const HEADER: usize = 48;
/// TD report body length.
pub const BODY: usize = 584;
/// SGX report (QE report) length.
pub const QE_REPORT: usize = 384;
/// Collateral older than its `nextUpdate` by more than this is refused.
pub const COLLATERAL_GRACE: u64 = 14 * 86_400;

/// A TD report body (TDX 1.x).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdReport {
    #[allow(missing_docs)]
    pub tee_tcb_svn: [u8; 16],
    #[allow(missing_docs)]
    pub mr_seam: [u8; 48],
    #[allow(missing_docs)]
    pub mr_signer_seam: [u8; 48],
    #[allow(missing_docs)]
    pub seam_attributes: [u8; 8],
    #[allow(missing_docs)]
    pub td_attributes: [u8; 8],
    #[allow(missing_docs)]
    pub xfam: [u8; 8],
    #[allow(missing_docs)]
    pub mr_td: [u8; 48],
    #[allow(missing_docs)]
    pub mr_config_id: [u8; 48],
    #[allow(missing_docs)]
    pub mr_owner: [u8; 48],
    #[allow(missing_docs)]
    pub mr_owner_config: [u8; 48],
    /// RTMR0–3.
    pub rtmr: [[u8; 48]; 4],
    /// REPORT_DATA: the binding (32 bytes) ‖ the agent package hash (32 bytes).
    pub report_data: [u8; 64],
}

impl Default for TdReport {
    fn default() -> Self {
        Self {
            tee_tcb_svn: [0; 16],
            mr_seam: [0; 48],
            mr_signer_seam: [0; 48],
            seam_attributes: [0; 8],
            td_attributes: [0; 8],
            xfam: [0; 8],
            mr_td: [0; 48],
            mr_config_id: [0; 48],
            mr_owner: [0; 48],
            mr_owner_config: [0; 48],
            rtmr: [[0; 48]; 4],
            report_data: [0; 64],
        }
    }
}

fn arr<const N: usize>(d: &[u8], p: usize) -> [u8; N] {
    d[p..p + N].try_into().unwrap()
}

impl TdReport {
    /// Parses the 584-byte body.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < BODY {
            return Err(Error::Quote("short TD report"));
        }
        Ok(Self {
            tee_tcb_svn: arr(b, 0),
            mr_seam: arr(b, 16),
            mr_signer_seam: arr(b, 64),
            seam_attributes: arr(b, 112),
            td_attributes: arr(b, 120),
            xfam: arr(b, 128),
            mr_td: arr(b, 136),
            mr_config_id: arr(b, 184),
            mr_owner: arr(b, 232),
            mr_owner_config: arr(b, 280),
            rtmr: [arr(b, 328), arr(b, 376), arr(b, 424), arr(b, 472)],
            report_data: arr(b, 520),
        })
    }

    /// The 584-byte encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(BODY);
        b.extend_from_slice(&self.tee_tcb_svn);
        b.extend_from_slice(&self.mr_seam);
        b.extend_from_slice(&self.mr_signer_seam);
        b.extend_from_slice(&self.seam_attributes);
        b.extend_from_slice(&self.td_attributes);
        b.extend_from_slice(&self.xfam);
        b.extend_from_slice(&self.mr_td);
        b.extend_from_slice(&self.mr_config_id);
        b.extend_from_slice(&self.mr_owner);
        b.extend_from_slice(&self.mr_owner_config);
        for r in &self.rtmr {
            b.extend_from_slice(r);
        }
        b.extend_from_slice(&self.report_data);
        b
    }

    /// The measurement images register for TDX: keccak256(MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2).
    pub fn measurement(&self) -> B256 {
        keccak256(Self::measurement_bytes(&self.mr_td, &self.rtmr[..3]))
    }

    /// The raw bytes hashed by [`measurement`](Self::measurement) (what `ImageRegistry` takes).
    pub fn measurement_bytes(mr_td: &[u8; 48], rtmr: &[[u8; 48]]) -> Vec<u8> {
        let mut m = mr_td.to_vec();
        for r in rtmr {
            m.extend_from_slice(r);
        }
        m
    }

    /// Whether the TD runs in debug mode (its memory is readable by the host).
    pub fn debug(&self) -> bool {
        self.td_attributes[0] & 1 != 0
    }
}

/// A verified quote.
#[derive(Debug, Clone)]
pub struct Verified {
    /// TCB status of the platform (see [`status`]).
    pub tcb_status: u8,
    /// Status of the quoting enclave.
    pub qe_status: u8,
    /// keccak256(PPID): the machine ID.
    pub machine_id: B256,
    /// The PCK certificate's SGX extension.
    pub pck: PckExtension,
    /// PCK certificate serial and issuer hash (for revocation checks).
    pub pck_serial: B256,
    #[allow(missing_docs)]
    pub pck_issuer: B256,
    /// The TD report.
    pub report: TdReport,
}

fn le(d: &[u8], p: usize, n: usize) -> Result<usize, Error> {
    let b = d.get(p..p + n).ok_or(Error::Quote("truncated"))?;
    Ok(b.iter().rev().fold(0usize, |a, &x| a << 8 | x as usize))
}

/// Verifies `quote` against `col` at time `now` (Unix seconds).
pub fn verify(quote: &[u8], col: &Collateral, now: u64) -> Result<Verified, Error> {
    let q = quote;
    if q.len() < HEADER + BODY + 4 + 128 + 6 {
        return Err(Error::Quote("short"));
    }
    if le(q, 0, 2)? != 4 {
        return Err(Error::Quote("version"));
    }
    if le(q, 2, 2)? != 2 {
        return Err(Error::Quote("attestation key type"));
    }
    if le(q, 4, 4)? != 0x81 {
        return Err(Error::Quote("not a TD quote"));
    }
    let report = TdReport::parse(&q[HEADER..HEADER + BODY])?;
    if report.debug() {
        return Err(Error::Quote("debug TD"));
    }
    let mut s = HEADER + BODY;
    let sig_len = le(q, s, 4)?;
    s += 4;
    if s + sig_len > q.len() {
        return Err(Error::Quote("signature data"));
    }
    let ak: Point = (arr(q, s + 64), arr(q, s + 96));
    if !p256_verify_raw(&q[..HEADER + BODY], &q[s..s + 64], &ak) {
        return Err(Error::Quote("TD report signature"));
    }
    let mut c = s + 128;
    if le(q, c, 2)? != 6 {
        return Err(Error::Quote("certification data type"));
    }
    c += 6;
    let qe = c;
    let qe_report = q.get(qe..qe + QE_REPORT).ok_or(Error::Quote("truncated"))?;
    let qe_sig = q.get(qe + QE_REPORT..qe + QE_REPORT + 64).ok_or(Error::Quote("truncated"))?;
    let auth_len = le(q, qe + QE_REPORT + 64, 2)?;
    let auth = qe + QE_REPORT + 66;
    let auth_data = q.get(auth..auth + auth_len).ok_or(Error::Quote("truncated"))?;
    let bind = sha256(&[&ak.0, &ak.1, auth_data]);
    if qe_report[320..352] != bind || qe_report[352..384] != [0u8; 32] {
        return Err(Error::Quote("QE report data"));
    }
    let cert = auth + auth_len;
    if le(q, cert, 2)? != 5 {
        return Err(Error::Quote("PCK chain type"));
    }
    let chain_len = le(q, cert + 2, 4)?;
    let pem = q.get(cert + 6..cert + 6 + chain_len).ok_or(Error::Quote("truncated"))?;
    let chain = pem_certs(pem)?;
    let leaf = chain.first().ok_or(Error::Quote("PCK chain"))?;
    let pck = Cert::parse(leaf)?;
    let ca = col.ca(&pck.issuer).ok_or(Error::Quote("unknown PCK issuer"))?;
    if now > ca.not_after || !pck.valid_at(now) {
        return Err(Error::Expired("PCK certificate"));
    }
    if !pck.signed_by(&ca.key) {
        return Err(Error::Signature("PCK certificate"));
    }
    if col.is_revoked(&pck.issuer, &pck.serial) {
        return Err(Error::Revoked);
    }
    if !p256_verify_raw(qe_report, qe_sig, &pck.key) {
        return Err(Error::Quote("QE report signature"));
    }
    let ext = PckExtension::of(&pck)?;
    let (tcb_status, next) = col.tdx_status(
        &ext.fmspc,
        &ext.comp_svn,
        ext.pcesvn,
        &report.tee_tcb_svn,
        &report.mr_signer_seam,
        &report.seam_attributes,
    );
    if tcb_status == status::UNKNOWN {
        return Err(Error::Quote("TCB level unknown"));
    }
    if now > next + COLLATERAL_GRACE {
        return Err(Error::Expired("TCB info"));
    }
    let (qe_status, next) = col.qe_status(
        &arr(qe_report, 16),
        &arr(qe_report, 48),
        &arr(qe_report, 128),
        le(qe_report, 256, 2)? as u16,
        le(qe_report, 258, 2)? as u16,
    );
    if qe_status == status::UNKNOWN {
        return Err(Error::Quote("quoting enclave unknown"));
    }
    if now > next + COLLATERAL_GRACE {
        return Err(Error::Expired("QE identity"));
    }
    Ok(Verified {
        tcb_status,
        qe_status,
        machine_id: keccak256(ext.ppid),
        pck_serial: pck.serial,
        pck_issuer: pck.issuer,
        pck: ext,
        report,
    })
}

/// Fields of a QE (SGX) report the verifier reads.
#[derive(Debug, Clone)]
pub struct QeReport {
    #[allow(missing_docs)]
    pub cpusvn: [u8; 16],
    #[allow(missing_docs)]
    pub miscselect: [u8; 4],
    #[allow(missing_docs)]
    pub attributes: [u8; 16],
    #[allow(missing_docs)]
    pub mrenclave: [u8; 32],
    #[allow(missing_docs)]
    pub mrsigner: [u8; 32],
    #[allow(missing_docs)]
    pub isvprodid: u16,
    #[allow(missing_docs)]
    pub isvsvn: u16,
    #[allow(missing_docs)]
    pub report_data: [u8; 64],
}

impl Default for QeReport {
    fn default() -> Self {
        Self {
            cpusvn: [0; 16],
            miscselect: [0; 4],
            attributes: [0; 16],
            mrenclave: [0; 32],
            mrsigner: [0; 32],
            isvprodid: 0,
            isvsvn: 0,
            report_data: [0; 64],
        }
    }
}

impl QeReport {
    /// The 384-byte encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; QE_REPORT];
        b[0..16].copy_from_slice(&self.cpusvn);
        b[16..20].copy_from_slice(&self.miscselect);
        b[48..64].copy_from_slice(&self.attributes);
        b[64..96].copy_from_slice(&self.mrenclave);
        b[128..160].copy_from_slice(&self.mrsigner);
        b[256..258].copy_from_slice(&self.isvprodid.to_le_bytes());
        b[258..260].copy_from_slice(&self.isvsvn.to_le_bytes());
        b[320..384].copy_from_slice(&self.report_data);
        b
    }
}
