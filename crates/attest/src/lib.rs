//! TEE attestation for Boltchain's enclave leases (ADR 0013).
//!
//! - [`tdx`]: Intel TDX quotes (DCAP v4), verified against [`intel::Collateral`] with the same
//!   steps and results as the on-chain `TdxVerifier` / `TeeCollateral`. Renters verify locally
//!   before handing secrets to an enclave.
//! - [`tpm`]: TPM 2.0 measured boot for T2 machines: quotes signed by an attestation key, the
//!   event log replayed into PCRs, the endorsement key certificate chain, and the credential
//!   challenge proving the attestation key lives in the same TPM. The verifier panel uses it.
//! - [`sim`] and [`tpm_sim`]: a simulated Intel PKI with TDX platforms, and a software TPM,
//!   for tests and development chains (never trusted on the public networks).

pub mod der;
pub mod intel;
pub mod sim;
pub mod tdx;
pub mod tpm;
pub mod tpm_sim;

pub use der::Point;
pub use intel::Collateral;

/// Why an attestation was refused.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed DER (certificate, CRL, extension).
    #[error("DER: {0}")]
    Der(&'static str),
    /// Malformed or unacceptable collateral.
    #[error("collateral: {0}")]
    Collateral(&'static str),
    /// A signature did not verify.
    #[error("bad signature: {0}")]
    Signature(&'static str),
    /// Outside a validity period.
    #[error("expired: {0}")]
    Expired(&'static str),
    /// A revoked certificate.
    #[error("revoked certificate")]
    Revoked,
    /// Malformed or unacceptable TDX quote.
    #[error("TDX quote: {0}")]
    Quote(&'static str),
    /// Malformed or unacceptable TPM evidence.
    #[error("TPM: {0}")]
    Tpm(String),
}
