//! Certificates and CRLs as the on-chain verifier sees them (P-256, ECDSA-SHA256), plus the
//! few DER helpers the SGX extension needs.

use crate::Error;
use alloy_primitives::{B256, keccak256};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use x509_parser::prelude::{FromDer, X509Certificate};

/// A DER element: (tag, content start, content length).
pub(crate) fn tlv(d: &[u8], p: usize) -> Result<(u8, usize, usize), Error> {
    let bad = || Error::Der("truncated element");
    let tag = *d.get(p).ok_or_else(bad)?;
    let first = *d.get(p + 1).ok_or_else(bad)?;
    let (start, len) = if first < 0x80 {
        (p + 2, first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(Error::Der("length"));
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *d.get(p + 2 + i).ok_or_else(bad)? as usize;
        }
        (p + 2 + n, len)
    };
    if start + len > d.len() {
        return Err(bad());
    }
    Ok((tag, start, len))
}

pub(crate) fn expect(d: &[u8], p: usize, tag: u8) -> Result<(usize, usize), Error> {
    let (t, s, n) = tlv(d, p)?;
    if t != tag {
        return Err(Error::Der("unexpected tag"));
    }
    Ok((s, n))
}

/// An unsigned big-endian integer right-aligned in 32 bytes (as `Der.integer32`).
pub(crate) fn int32(bytes: &[u8]) -> Result<B256, Error> {
    let b = {
        let mut b = bytes;
        while let [0, rest @ ..] = b {
            b = rest;
        }
        b
    };
    if b.len() > 32 {
        return Err(Error::Der("integer too long"));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(B256::from(out))
}

/// A P-256 public key as (x, y).
pub type Point = ([u8; 32], [u8; 32]);

/// Verifies a P-256 ECDSA-SHA256 signature (r ‖ s, or DER) over `msg`.
pub fn p256_verify(msg: &[u8], sig: &Signature, key: &Point) -> bool {
    let mut sec1 = [4u8; 65];
    sec1[1..33].copy_from_slice(&key.0);
    sec1[33..].copy_from_slice(&key.1);
    match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(k) => k.verify(msg, sig).is_ok(),
        Err(_) => false,
    }
}

/// Verifies a raw 64-byte r ‖ s signature.
pub fn p256_verify_raw(msg: &[u8], sig: &[u8], key: &Point) -> bool {
    match Signature::from_slice(sig) {
        Ok(s) => p256_verify(msg, &s, key),
        Err(_) => false,
    }
}

/// A certificate with a P-256 key signed with ECDSA-SHA256 (all Intel attestation certificates).
#[derive(Debug, Clone)]
pub struct Cert {
    /// The whole certificate.
    pub der: Vec<u8>,
    /// To-be-signed part.
    pub tbs: Vec<u8>,
    /// Serial number, right-aligned.
    pub serial: B256,
    /// keccak256 of the issuer Name element.
    pub issuer: B256,
    /// keccak256 of the subject Name element.
    pub subject: B256,
    /// Validity, Unix seconds.
    pub not_before: u64,
    /// Validity, Unix seconds.
    pub not_after: u64,
    /// Subject public key.
    pub key: Point,
    sig: Signature,
    ext: Vec<(String, Vec<u8>)>,
}

impl Cert {
    /// Parses a DER certificate.
    pub fn parse(der: &[u8]) -> Result<Self, Error> {
        let (_, c) = X509Certificate::from_der(der).map_err(|_| Error::Der("certificate"))?;
        let pk = &c.public_key().subject_public_key.data;
        if pk.len() != 65 || pk[0] != 4 {
            return Err(Error::Der("not a P-256 key"));
        }
        let key = (pk[1..33].try_into().unwrap(), pk[33..].try_into().unwrap());
        let sig = Signature::from_der(&c.signature_value.data)
            .map_err(|_| Error::Der("signature"))?;
        let ext = c
            .extensions()
            .iter()
            .map(|e| (e.oid.to_id_string(), e.value.to_vec()))
            .collect();
        Ok(Self {
            der: der.to_vec(),
            tbs: c.tbs_certificate.as_ref().to_vec(),
            serial: int32(c.raw_serial())?,
            issuer: keccak256(c.issuer().as_raw()),
            subject: keccak256(c.subject().as_raw()),
            not_before: c.validity().not_before.timestamp() as u64,
            not_after: c.validity().not_after.timestamp() as u64,
            key,
            sig,
            ext,
        })
    }

    /// Whether the certificate is signed by `key`.
    pub fn signed_by(&self, key: &Point) -> bool {
        p256_verify(&self.tbs, &self.sig, key)
    }

    /// Whether it is valid at `now`.
    pub fn valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// The value of the extension with dotted OID `oid`.
    pub fn extension(&self, oid: &str) -> Option<&[u8]> {
        self.ext.iter().find(|(o, _)| o == oid).map(|(_, v)| v.as_slice())
    }
}

/// A CRL signed with ECDSA-SHA256.
#[derive(Debug, Clone)]
pub struct Crl {
    /// keccak256 of the issuer Name element.
    pub issuer: B256,
    /// Unix seconds.
    pub this_update: u64,
    /// Unix seconds (0 if absent).
    pub next_update: u64,
    /// Revoked serial numbers, right-aligned.
    pub serials: Vec<B256>,
    tbs: Vec<u8>,
    sig: Signature,
}

impl Crl {
    /// Parses a DER CRL.
    pub fn parse(der: &[u8]) -> Result<Self, Error> {
        use x509_parser::revocation_list::CertificateRevocationList;
        let (_, l) =
            CertificateRevocationList::from_der(der).map_err(|_| Error::Der("CRL"))?;
        let sig =
            Signature::from_der(&l.signature_value.data).map_err(|_| Error::Der("signature"))?;
        let mut serials = Vec::new();
        for r in l.iter_revoked_certificates() {
            serials.push(int32(r.raw_serial())?);
        }
        Ok(Self {
            issuer: keccak256(l.issuer().as_raw()),
            this_update: l.last_update().timestamp() as u64,
            next_update: l.next_update().map(|t| t.timestamp() as u64).unwrap_or(0),
            serials,
            tbs: l.tbs_cert_list.as_ref().to_vec(),
            sig,
        })
    }

    /// Whether the CRL is signed by `key`.
    pub fn signed_by(&self, key: &Point) -> bool {
        p256_verify(&self.tbs, &self.sig, key)
    }
}

/// Splits a PEM chain into DER certificates.
pub fn pem_certs(pem: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let text = std::str::from_utf8(pem).map_err(|_| Error::Der("PEM"))?;
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block.split("-----END CERTIFICATE-----").next().unwrap_or("");
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        out.push(base64_decode(&b64).ok_or(Error::Der("base64"))?);
    }
    Ok(out)
}

pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub(crate) fn base64_encode(d: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in d.chunks(3) {
        let n = c.len();
        let v = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= n {
                s.push(A[(v >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// PEM-encodes DER certificates.
pub fn pem_encode(certs: &[&[u8]]) -> String {
    let mut s = String::new();
    for c in certs {
        s.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in base64_encode(c).as_bytes().chunks(64) {
            s.push_str(std::str::from_utf8(line).unwrap());
            s.push('\n');
        }
        s.push_str("-----END CERTIFICATE-----\n");
    }
    s
}
