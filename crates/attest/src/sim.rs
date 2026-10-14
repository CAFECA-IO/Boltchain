//! A simulated Intel attestation PKI and TDX platform, for tests and development chains.
//!
//! It mirrors Intel's structure (root CA → PCK platform CA → PCK certificates with the SGX
//! extension; root CA → TCB signing certificate for TCB info and QE identity; CRLs) under a
//! test root generated from a seed. A development chain's genesis installs that root in
//! `TeeCollateral` instead of Intel's (`devTeeRoot`), so quotes made here verify there. Names
//! say "Boltchain Simulated", never Intel.

use crate::{
    der::{Point, pem_encode},
    intel::sha256,
    tdx::{BODY, HEADER, QeReport, TdReport},
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePrivateKey,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CustomExtension, DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevokedCertParams, SerialNumber, date_time_ymd,
};

/// Simulated FMSPC.
pub const FMSPC: [u8; 6] = [0x00, 0x90, 0x6e, 0xd5, 0x00, 0x00];
/// The simulated platform's SGX component SVNs and PCE SVN.
pub const COMP_SVN: [u8; 16] = [3; 16];
#[allow(missing_docs)]
pub const PCESVN: u16 = 13;
/// TEE_TCB_SVN of simulated TDs: module SVN 5, major version 1, TDX components from index 2.
pub const TEE_TCB_SVN: [u8; 16] = [5, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Simulated QE identity.
pub const QE_ISVPRODID: u16 = 2;
#[allow(missing_docs)]
pub const QE_ISVSVN: u16 = 4;
/// Collateral dates (Unix seconds): issued 2026-01-01, next update 2049-01-01.
pub const ISSUED: &str = "2026-01-01T00:00:00Z";
#[allow(missing_docs)]
pub const NEXT_UPDATE: &str = "2049-01-01T00:00:00Z";

fn key(seed: &[u8], label: &str) -> SigningKey {
    let mut ctr = 0u8;
    loop {
        let k = sha256(&[b"boltchain/attest/sim", seed, label.as_bytes(), &[ctr]]);
        if let Ok(s) = SigningKey::from_slice(&k) {
            return s;
        }
        ctr += 1;
    }
}

fn keypair(k: &SigningKey) -> KeyPair {
    let der = k.to_pkcs8_der().expect("pkcs8");
    KeyPair::try_from(der.as_bytes()).expect("key pair")
}

/// The public point of a signing key.
pub fn point(k: &SigningKey) -> Point {
    let p = k.verifying_key().to_encoded_point(false);
    (<[u8; 32]>::from(*p.x().unwrap()), <[u8; 32]>::from(*p.y().unwrap()))
}

fn params(cn: &str, serial: u64, ca: Option<u8>) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "Boltchain Simulated TEE");
    dn.push(DnType::CountryName, "TW");
    p.distinguished_name = dn;
    p.not_before = date_time_ymd(2020, 1, 1);
    p.not_after = date_time_ymd(2049, 12, 31);
    p.serial_number = Some(SerialNumber::from(serial.to_be_bytes().to_vec()));
    p.key_identifier_method = KeyIdMethod::Sha256;
    match ca {
        None => {
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages =
                vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::ContentCommitment];
        }
        Some(depth) => {
            p.is_ca = IsCa::Ca(if depth == u8::MAX {
                BasicConstraints::Unconstrained
            } else {
                BasicConstraints::Constrained(depth)
            });
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        }
    }
    p
}

// ------------------------------------------------------------------ DER for the SGX extension

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut c = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut tmp = vec![(a & 0x7f) as u8];
        let mut v = a >> 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        c.extend(tmp);
    }
    der(0x06, &c)
}

fn int(v: u64) -> Vec<u8> {
    let mut b = v.to_be_bytes().to_vec();
    while b.len() > 1 && b[0] == 0 {
        b.remove(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    der(0x02, &b)
}

const SGX: [u64; 7] = [1, 2, 840, 113741, 1, 13, 1];

fn sgx(arcs: &[u64]) -> Vec<u8> {
    let mut a = SGX.to_vec();
    a.extend_from_slice(arcs);
    oid(&a)
}

fn pair(o: Vec<u8>, v: Vec<u8>) -> Vec<u8> {
    der(0x30, &[o, v].concat())
}

/// The SGX extension of a PCK certificate.
pub fn sgx_extension(
    ppid: &[u8; 16],
    comp_svn: &[u8; 16],
    pcesvn: u16,
    fmspc: &[u8; 6],
) -> Vec<u8> {
    let mut tcb = Vec::new();
    for (i, s) in comp_svn.iter().enumerate() {
        tcb.extend(pair(sgx(&[2, i as u64 + 1]), int(*s as u64)));
    }
    tcb.extend(pair(sgx(&[2, 17]), int(pcesvn as u64)));
    tcb.extend(pair(sgx(&[2, 18]), der(0x04, comp_svn)));
    let items = [
        pair(sgx(&[1]), der(0x04, ppid)),
        pair(sgx(&[2]), der(0x30, &tcb)),
        pair(sgx(&[3]), der(0x04, &[0, 0])),
        pair(sgx(&[4]), der(0x04, fmspc)),
        pair(sgx(&[5]), der(0x0a, &[0])),
    ]
    .concat();
    der(0x30, &items)
}

// ------------------------------------------------------------------ the PKI

/// A simulated Intel-style attestation PKI.
pub struct SimIntel {
    seed: Vec<u8>,
    root_key: SigningKey,
    root: Certificate,
    root_kp: KeyPair,
    platform_ca: Certificate,
    platform_kp: KeyPair,
    tcb_key: SigningKey,
    tcb: Certificate,
}

impl std::fmt::Debug for SimIntel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimIntel").field("root", &self.root_point()).finish()
    }
}

/// Collateral to submit to `TeeCollateral` (or a [`Collateral`](crate::Collateral)).
#[derive(Debug, Clone)]
pub struct SimCollateral {
    /// CA certificates: PCK platform CA, TCB signing.
    pub cas: Vec<Vec<u8>>,
    /// CRLs: root CA's, PCK platform CA's.
    pub crls: Vec<Vec<u8>>,
    /// TDX TCB info JSON.
    pub tcb_info: String,
    /// TD_QE identity JSON.
    pub qe_identity: String,
}

impl SimIntel {
    /// The PKI generated from `seed` (same seed, same keys).
    pub fn new(seed: &[u8]) -> Self {
        let root_key = key(seed, "root");
        let root_kp = keypair(&root_key);
        let root = params("Boltchain Simulated TEE Root CA", 1, Some(u8::MAX))
            .self_signed(&root_kp)
            .expect("root");
        let platform_kp = keypair(&key(seed, "platform"));
        let platform_ca = params("Boltchain Simulated PCK Platform CA", 2, Some(0))
            .signed_by(&platform_kp, &root, &root_kp)
            .expect("platform CA");
        let tcb_key = key(seed, "tcb");
        let tcb = params("Boltchain Simulated TCB Signing", 3, None)
            .signed_by(&keypair(&tcb_key), &root, &root_kp)
            .expect("TCB signing");
        Self {
            seed: seed.to_vec(),
            root_key,
            root,
            root_kp,
            platform_ca,
            platform_kp,
            tcb_key,
            tcb,
        }
    }

    /// The development PKI every dev chain trusts (`boltchain genesis make-dev`).
    pub fn dev() -> Self {
        Self::new(b"boltchain-dev")
    }

    /// The root public key.
    pub fn root_point(&self) -> Point {
        point(&self.root_key)
    }

    /// Root certificate (DER).
    pub fn root_der(&self) -> Vec<u8> {
        self.root.der().to_vec()
    }

    fn sign_json(&self, field: &str, body: &str) -> String {
        let sig: Signature = self.tcb_key.sign(body.as_bytes());
        format!("{{\"{field}\":{body},\"signature\":\"{}\"}}", hex::encode(sig.to_bytes()))
    }

    /// TDX TCB info v3 for the simulated platform, with evaluation number `evaluation`.
    /// `up_to_date`: whether the simulated platform's TCB is the latest level.
    pub fn tcb_info(&self, evaluation: u32, up_to_date: bool) -> String {
        let comps = |v: &[u8; 16]| {
            let items: Vec<String> = v.iter().map(|s| format!("{{\"svn\":{s}}}")).collect();
            format!("[{}]", items.join(","))
        };
        let mut tdx_cur = [0u8; 16];
        tdx_cur[0] = TEE_TCB_SVN[0];
        tdx_cur[1] = TEE_TCB_SVN[1];
        tdx_cur[2] = TEE_TCB_SVN[2];
        let mut newer_sgx = COMP_SVN;
        newer_sgx[0] += 1;
        let level = |sgx: &[u8; 16], pcesvn: u16, tdx: &[u8; 16], status: &str| {
            format!(
                "{{\"tcb\":{{\"sgxtcbcomponents\":{},\"pcesvn\":{pcesvn},\"tdxtcbcomponents\":{}}},\"tcbDate\":\"{ISSUED}\",\"tcbStatus\":\"{status}\"}}",
                comps(sgx),
                comps(tdx)
            )
        };
        let mut levels = Vec::new();
        if !up_to_date {
            levels.push(level(&newer_sgx, PCESVN, &tdx_cur, "UpToDate"));
        }
        levels.push(level(
            &COMP_SVN,
            PCESVN,
            &tdx_cur,
            if up_to_date { "UpToDate" } else { "OutOfDate" },
        ));
        levels.push(level(&[0; 16], 0, &[0; 16], "OutOfDate"));
        let zero48 = "00".repeat(48);
        let body = format!(
            "{{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"{ISSUED}\",\"nextUpdate\":\"{NEXT_UPDATE}\",\"fmspc\":\"{}\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":{evaluation},\"tdxModule\":{{\"mrsigner\":\"{zero48}\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"}},\"tdxModuleIdentities\":[{{\"id\":\"TDX_01\",\"mrsigner\":\"{zero48}\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{{\"tcb\":{{\"isvsvn\":{}}},\"tcbDate\":\"{ISSUED}\",\"tcbStatus\":\"UpToDate\"}}]}}],\"tcbLevels\":[{}]}}",
            hex::encode_upper(FMSPC),
            TEE_TCB_SVN[0],
            levels.join(",")
        );
        self.sign_json("tcbInfo", &body)
    }

    /// The simulated quoting enclave's MRSIGNER.
    pub fn qe_mrsigner() -> [u8; 32] {
        sha256(&[b"boltchain simulated quoting enclave"])
    }

    /// TD_QE identity, with evaluation number `evaluation`.
    pub fn qe_identity(&self, evaluation: u32) -> String {
        let body = format!(
            "{{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"{ISSUED}\",\"nextUpdate\":\"{NEXT_UPDATE}\",\"tcbEvaluationDataNumber\":{evaluation},\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"{}\",\"isvprodid\":{QE_ISVPRODID},\"tcbLevels\":[{{\"tcb\":{{\"isvsvn\":{QE_ISVSVN}}},\"tcbDate\":\"{ISSUED}\",\"tcbStatus\":\"UpToDate\"}}]}}",
            hex::encode_upper(Self::qe_mrsigner())
        );
        self.sign_json("enclaveIdentity", &body)
    }

    /// A CRL from the root (`platform = false`) or the PCK platform CA, revoking `serials`,
    /// issued at `this_update` (days after 2026-01-01).
    pub fn crl(&self, platform: bool, serials: &[u64], this_update: u32) -> Vec<u8> {
        let t = date_time_ymd(2026, 1, 1) + time::Duration::days(this_update as i64);
        let p = CertificateRevocationListParams {
            this_update: t,
            next_update: date_time_ymd(2049, 1, 1),
            crl_number: SerialNumber::from(vec![this_update as u8 + 1]),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(s.to_be_bytes().to_vec()),
                    revocation_time: t,
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let l = if platform {
            p.signed_by(&self.platform_ca, &self.platform_kp)
        } else {
            p.signed_by(&self.root, &self.root_kp)
        };
        l.expect("CRL").der().to_vec()
    }

    /// Everything a chain needs to verify simulated quotes.
    pub fn collateral(&self) -> SimCollateral {
        SimCollateral {
            cas: vec![self.platform_ca.der().to_vec(), self.tcb.der().to_vec()],
            crls: vec![self.crl(false, &[], 0), self.crl(true, &[], 0)],
            tcb_info: self.tcb_info(1, true),
            qe_identity: self.qe_identity(1),
        }
    }

    /// A simulated TDX machine; `id` selects its keys and PPID.
    pub fn platform(&self, id: u64) -> SimPlatform {
        let label = format!("platform/{id}");
        let pck_key = key(&self.seed, &format!("{label}/pck"));
        let ppid: [u8; 16] =
            sha256(&[&self.seed, label.as_bytes(), b"ppid"])[..16].try_into().unwrap();
        let mut p = params("Boltchain Simulated PCK Certificate", 1000 + id, None);
        p.custom_extensions = vec![CustomExtension::from_oid_content(
            &SGX,
            sgx_extension(&ppid, &COMP_SVN, PCESVN, &FMSPC),
        )];
        let pck =
            p.signed_by(&keypair(&pck_key), &self.platform_ca, &self.platform_kp).expect("PCK");
        let chain = pem_encode(&[pck.der(), self.platform_ca.der(), self.root.der()]);
        SimPlatform {
            ppid,
            serial: 1000 + id,
            pck_key,
            ak_key: key(&self.seed, &format!("{label}/ak")),
            chain,
        }
    }
}

/// A simulated TDX machine.
pub struct SimPlatform {
    /// Platform provisioning ID (the machine ID is its keccak256).
    pub ppid: [u8; 16],
    /// PCK certificate serial number.
    pub serial: u64,
    pck_key: SigningKey,
    ak_key: SigningKey,
    chain: String,
}

impl std::fmt::Debug for SimPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimPlatform").field("ppid", &hex::encode(self.ppid)).finish()
    }
}

impl SimPlatform {
    /// keccak256(PPID).
    pub fn machine_id(&self) -> alloy_primitives::B256 {
        alloy_primitives::keccak256(self.ppid)
    }

    /// A TD report for this platform with the given measurements and REPORT_DATA.
    pub fn td_report(mr_td: [u8; 48], rtmr: [[u8; 48]; 4], report_data: [u8; 64]) -> TdReport {
        TdReport { tee_tcb_svn: TEE_TCB_SVN, mr_td, rtmr, report_data, ..Default::default() }
    }

    /// A quote over `report`.
    pub fn quote(&self, report: &TdReport) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&4u16.to_le_bytes());
        q.extend_from_slice(&2u16.to_le_bytes());
        q.extend_from_slice(&0x81u32.to_le_bytes());
        q.extend_from_slice(&[0u8; 4]);
        q.extend_from_slice(&[0u8; 16]); // QE vendor ID
        q.extend_from_slice(&[0u8; 20]); // user data
        debug_assert_eq!(q.len(), HEADER);
        q.extend_from_slice(&report.encode());
        debug_assert_eq!(q.len(), HEADER + BODY);
        let sig: Signature = self.ak_key.sign(&q);
        let ak = point(&self.ak_key);
        let auth: Vec<u8> = (0u8..32).collect();
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&sha256(&[&ak.0, &ak.1, &auth]));
        let qe = QeReport {
            attributes: {
                let mut a = [0u8; 16];
                a[0] = 0x11;
                a
            },
            mrsigner: SimIntel::qe_mrsigner(),
            isvprodid: QE_ISVPRODID,
            isvsvn: QE_ISVSVN,
            report_data: rd,
            ..Default::default()
        }
        .encode();
        let qe_sig: Signature = self.pck_key.sign(&qe);
        let pem = self.chain.as_bytes();
        let mut cert = Vec::new();
        cert.extend_from_slice(&qe);
        cert.extend_from_slice(&qe_sig.to_bytes());
        cert.extend_from_slice(&(auth.len() as u16).to_le_bytes());
        cert.extend_from_slice(&auth);
        cert.extend_from_slice(&5u16.to_le_bytes());
        cert.extend_from_slice(&(pem.len() as u32).to_le_bytes());
        cert.extend_from_slice(pem);
        let mut sd = Vec::new();
        sd.extend_from_slice(&sig.to_bytes());
        sd.extend_from_slice(&ak.0);
        sd.extend_from_slice(&ak.1);
        sd.extend_from_slice(&6u16.to_le_bytes());
        sd.extend_from_slice(&(cert.len() as u32).to_le_bytes());
        sd.extend_from_slice(&cert);
        q.extend_from_slice(&(sd.len() as u32).to_le_bytes());
        q.extend_from_slice(&sd);
        q
    }
}
