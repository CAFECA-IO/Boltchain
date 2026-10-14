//! A software TPM for tests and development: an RSA-2048 endorsement key certified by a
//! simulated TPM vendor CA, an ECC P-256 attestation key, SHA-256 PCRs with a crypto-agile
//! event log, quotes, and ActivateCredential.

use crate::{
    Error,
    intel::sha256,
    sim::point,
    tpm::{
        AK_ATTRIBUTES, EccPublic, Event, Evidence, Quote, USER_WITH_AUTH, encode_log,
        encode_signature, open_credential, pcr_digest,
    },
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePrivateKey,
};
use rand_core::{CryptoRng, RngCore};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SerialNumber, date_time_ymd,
};
use rsa::{Oaep, RsaPrivateKey, pkcs8::EncodePublicKey};
use sha2::Sha256;

/// A deterministic RNG (SHA-256 in counter mode) so simulated keys follow from a seed.
#[derive(Debug, Clone)]
pub struct SeedRng {
    seed: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
}

impl SeedRng {
    /// The stream for `seed`.
    pub fn new(seed: &[u8]) -> Self {
        Self { seed: sha256(&[b"boltchain/attest/rng", seed]), counter: 0, buf: Vec::new() }
    }
}

impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            if self.buf.is_empty() {
                self.buf = sha256(&[&self.seed, &self.counter.to_le_bytes()]).to_vec();
                self.counter += 1;
            }
            *d = self.buf.remove(0);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeedRng {}

fn p256_key(seed: &[u8], label: &str) -> SigningKey {
    let mut ctr = 0u8;
    loop {
        if let Ok(k) =
            SigningKey::from_slice(&sha256(&[b"boltchain/tpm-sim", seed, label.as_bytes(), &[ctr]]))
        {
            return k;
        }
        ctr += 1;
    }
}

fn name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "Boltchain Simulated TPM");
    dn.push(DnType::CountryName, "TW");
    dn
}

/// A simulated TPM vendor CA.
pub struct SimTpmCa {
    cert: Certificate,
    key: KeyPair,
}

impl std::fmt::Debug for SimTpmCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimTpmCa").finish_non_exhaustive()
    }
}

impl SimTpmCa {
    /// The CA generated from `seed`.
    pub fn new(seed: &[u8]) -> Self {
        let k = p256_key(seed, "vendor-root");
        let key = KeyPair::try_from(k.to_pkcs8_der().expect("pkcs8").as_bytes()).expect("key");
        let mut p = CertificateParams::default();
        p.distinguished_name = name("Boltchain Simulated TPM Root CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.not_before = date_time_ymd(2020, 1, 1);
        p.not_after = date_time_ymd(2049, 12, 31);
        p.serial_number = Some(SerialNumber::from(vec![1]));
        let cert = p.self_signed(&key).expect("TPM root");
        Self { cert, key }
    }

    /// The CA development chains' verifier panels trust.
    pub fn dev() -> Self {
        Self::new(b"boltchain-dev")
    }

    /// Root certificate (DER).
    pub fn root_der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }
}

/// A software TPM.
pub struct SoftTpm {
    ek: RsaPrivateKey,
    ek_cert: Vec<u8>,
    ak: SigningKey,
    ak_public: EccPublic,
    pcrs: [[u8; 32]; 24],
    events: Vec<Event>,
    clock: u64,
}

impl std::fmt::Debug for SoftTpm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftTpm").field("events", &self.events.len()).finish_non_exhaustive()
    }
}

impl SoftTpm {
    /// A TPM whose keys follow from `seed`, with an EK certificate from `ca`.
    pub fn new(seed: &[u8], ca: &SimTpmCa) -> Self {
        let mut rng = SeedRng::new(&[b"ek/".as_slice(), seed].concat());
        let ek = RsaPrivateKey::new(&mut rng, 2048).expect("EK");
        let ek_kp =
            KeyPair::try_from(ek.to_pkcs8_der().expect("pkcs8").as_bytes()).expect("EK key pair");
        let mut p = CertificateParams::default();
        p.distinguished_name = name("Boltchain Simulated EK");
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
        p.not_before = date_time_ymd(2020, 1, 1);
        p.not_after = date_time_ymd(2049, 12, 31);
        p.serial_number = Some(SerialNumber::from(sha256(&[seed])[..8].to_vec()));
        let ek_cert =
            p.signed_by(&ek_kp, &ca.cert, &ca.key).expect("EK certificate").der().to_vec();
        let ak = p256_key(seed, "ak");
        let ak_public = EccPublic::new(AK_ATTRIBUTES | USER_WITH_AUTH, point(&ak));
        Self { ek, ek_cert, ak, ak_public, pcrs: [[0; 32]; 24], events: Vec::new(), clock: 0 }
    }

    /// The EK's SubjectPublicKeyInfo (DER).
    pub fn ek_spki(&self) -> Vec<u8> {
        self.ek.to_public_key().to_public_key_der().expect("SPKI").as_bytes().to_vec()
    }

    /// The machine ID: keccak256 of the EK's SubjectPublicKeyInfo.
    pub fn machine_id(&self) -> alloy_primitives::B256 {
        alloy_primitives::keccak256(self.ek_spki())
    }

    /// The AK's name.
    pub fn ak_name(&self) -> Vec<u8> {
        self.ak_public.name()
    }

    /// Measures `data` into `pcr` (logged).
    pub fn extend(&mut self, pcr: u32, kind: u32, data: &[u8]) {
        let digest = sha256(&[data]);
        let mut h = sha2::Sha256::default();
        sha2::Digest::update(&mut h, self.pcrs[pcr as usize]);
        sha2::Digest::update(&mut h, digest);
        self.pcrs[pcr as usize] = sha2::Digest::finalize(h).into();
        self.events.push(Event { pcr, kind, digest, data: data.to_vec() });
    }

    /// Current PCR values.
    pub fn pcrs(&self) -> &[[u8; 32]; 24] {
        &self.pcrs
    }

    /// A measured boot of `image` (firmware stages into PCRs 0–7, the image into 11).
    pub fn boot(&mut self, image: &[u8]) {
        for pcr in 0..8 {
            self.extend(pcr, 0x8000_0008, format!("simulated firmware stage {pcr}").as_bytes());
        }
        self.extend(11, crate::tpm::EV_IPL, image);
    }

    /// Quotes the PCRs in `mask` with `qualifying` data.
    pub fn quote(&mut self, mask: u32, qualifying: &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.clock += 1000;
        let q = Quote {
            signer: self.ak_name(),
            extra_data: qualifying.to_vec(),
            clock: self.clock,
            reset_count: 0,
            restart_count: 0,
            safe: true,
            firmware: 0x0001_0002_0003_0004,
            pcr_mask: mask,
            pcr_digest: pcr_digest(&self.pcrs, mask).to_vec(),
        }
        .encode();
        let sig: Signature = self.ak.sign(&q);
        let b = sig.to_bytes();
        (q, encode_signature(&b[..32], &b[32..]))
    }

    /// Evidence for appraisal: EK certificate, AK, a quote of `mask` over `qualifying`, the
    /// event log.
    pub fn evidence(&mut self, mask: u32, qualifying: &[u8]) -> Evidence {
        let (quote, signature) = self.quote(mask, qualifying);
        Evidence {
            ek_cert: self.ek_cert.clone(),
            ek_chain: vec![],
            ak_public: self.ak_public.raw.clone(),
            quote,
            signature,
            event_log: encode_log(&self.events),
        }
    }

    /// ActivateCredential: recovers the secret of a challenge made for this TPM's EK and AK.
    pub fn activate_credential(
        &self,
        blob: &[u8],
        encrypted_secret: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let n = u16::from_be_bytes(
            encrypted_secret.get(..2).ok_or(Error::Tpm("secret".into()))?.try_into().unwrap(),
        ) as usize;
        let ct = encrypted_secret.get(2..2 + n).ok_or(Error::Tpm("secret".into()))?;
        let seed = self
            .ek
            .decrypt(Oaep::new_with_label::<Sha256, _>("IDENTITY\0"), ct)
            .map_err(|_| Error::Tpm("credential secret".into()))?;
        open_credential(&seed, &self.ak_name(), blob)
    }
}
