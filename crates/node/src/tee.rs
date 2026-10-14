//! TEE agent leasing from the command line (ADR 0013).
//!
//! - `boltchain image`: register agent runtime images and their measurements.
//! - `boltchain collateral`: submit Intel's attestation collateral (anyone may; Intel signs it).
//! - `boltchain enclave`: the operator's side — register a machine, offer it, bond, activate
//!   leases, and (`enclave runtime --simulate`) a simulated agent runtime for development.
//! - `boltchain lease`: the renter's side — find offers, lease, verify the enclave locally,
//!   deliver secrets, migrate, end; give the enclave a limited wallet.

use crate::{
    relay::through_relay,
    wallet::{format_bolt, http, load_wallet, parse_bolt, rpc, send_delegated, send_tx},
};
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use anyhow::{Context, Result, bail};
use bolt_attest::{
    Collateral,
    sim::{SimIntel, SimPlatform},
    tdx::{self, TdReport},
    tpm::{self, Evidence},
    tpm_sim::{SimTpmCa, SoftTpm},
};
use bolt_system::{abi::*, addresses::*};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

const RPC: &str = "http://127.0.0.1:8545";

/// Machine kinds.
pub const TDX: u8 = 1;
#[allow(missing_docs)]
pub const TPM: u8 = 3;

/// Lease states.
pub mod state {
    /// Waiting for the enclave's attestation.
    pub const PENDING: u8 = 1;
    /// Attestation with the verifier panel.
    pub const VERIFYING: u8 = 2;
    #[allow(missing_docs)]
    pub const ACTIVE: u8 = 3;
    #[allow(missing_docs)]
    pub const ENDED: u8 = 4;

    /// Name of a state.
    pub fn name(s: u8) -> &'static str {
        match s {
            PENDING => "pending",
            VERIFYING => "verifying",
            ACTIVE => "active",
            ENDED => "ended",
            _ => "?",
        }
    }
}

/// The simulated runtime's TDX measurements (MRTD, RTMR0–2) and its TPM boot image.
pub const SIM_MRTD: [u8; 48] = [0x5a; 48];
#[allow(missing_docs)]
pub const SIM_RTMR: [[u8; 48]; 3] = [[0x01; 48], [0x02; 48], [0x03; 48]];
#[allow(missing_docs)]
pub const SIM_TPM_IMAGE: &[u8] = b"bolt-art simulated runtime";

/// The measurement bytes `ImageRegistry` takes for the simulated runtime of `kind`.
pub fn sim_measurement(kind: u8) -> Vec<u8> {
    if kind == TDX {
        TdReport::measurement_bytes(&SIM_MRTD, &SIM_RTMR)
    } else {
        let mut t = SoftTpm::new(b"measure", &SimTpmCa::dev());
        t.boot(SIM_TPM_IMAGE);
        tpm::measurement_bytes(tpm::DEFAULT_PCRS, &tpm::selected(t.pcrs(), tpm::DEFAULT_PCRS))
    }
}

fn parse_kind(s: &str) -> Result<u8> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "tdx" | "t1" => TDX,
        "tpm" | "t2" => TPM,
        _ => bail!("kind is tdx or tpm"),
    })
}

fn kind_name(k: u8) -> &'static str {
    match k {
        TDX => "TDX (T1)",
        TPM => "TPM (T2)",
        _ => "?",
    }
}

/// eth_call against `to`.
pub fn call<C: SolCall>(url: &str, to: Address, c: C) -> Result<C::Return> {
    let out = rpc(
        url,
        "eth_call",
        json!([{"to": to, "data": hex::encode_prefixed(c.abi_encode())}, "latest"]),
    )?;
    let bytes: Bytes = serde_json::from_value(out)?;
    Ok(C::abi_decode_returns(&bytes)?)
}

fn first_topic(url: &str, hash: B256, sig: &str) -> Result<U256> {
    let topic = keccak256(sig.as_bytes());
    let r = rpc(url, "eth_getTransactionReceipt", json!([hash]))?;
    for log in r["logs"].as_array().into_iter().flatten() {
        let topics: Vec<B256> = serde_json::from_value(log["topics"].clone()).unwrap_or_default();
        if topics.first() == Some(&topic) && topics.len() > 1 {
            return Ok(U256::from_be_bytes(topics[1].0));
        }
    }
    bail!("event {sig} not found in transaction {hash}")
}

fn hex32(s: &str) -> Result<B256> {
    s.parse::<B256>().with_context(|| format!("expected 32 bytes of hex: {s}"))
}

/// A 32-byte hash given as hex, or the keccak256 of a file.
fn hash_arg(s: &str) -> Result<B256> {
    if let Ok(h) = s.parse::<B256>() {
        return Ok(h);
    }
    let data = std::fs::read(s).with_context(|| format!("{s} is neither a hash nor a file"))?;
    Ok(keccak256(&data))
}

fn tcb_name(s: u8) -> &'static str {
    bolt_attest::intel::status::name(s)
}

// ===================================================================== image

/// `boltchain image`.
#[derive(Debug, clap::Subcommand)]
pub enum ImageCmd {
    /// Register a runtime image: its source (CID) and how to build it reproducibly.
    Register {
        /// Account key file (pays the gas).
        #[arg(long)]
        wallet: PathBuf,
        /// Display name.
        #[arg(long)]
        name: String,
        /// CID (or URL) of the source tree.
        #[arg(long)]
        source: String,
        /// How to build it, e.g. "nix build .#bolt-art".
        #[arg(long, default_value = "")]
        build: String,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Add a measurement the image yields on some hardware (the image's registrant only).
    Measure {
        /// Account key file (the image's registrant).
        #[arg(long)]
        wallet: PathBuf,
        /// Image id.
        #[arg(long)]
        image: u64,
        /// tdx or tpm.
        #[arg(long)]
        kind: String,
        /// TDX: MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2 (192 bytes, hex).
        #[arg(long)]
        tdx: Option<String>,
        /// TPM: a T2 machine's evidence file (its replayed PCRs are the measurement).
        #[arg(long)]
        evidence: Option<PathBuf>,
        /// The simulated runtime's measurement (development chains).
        #[arg(long)]
        simulate: bool,
        /// Hardware and firmware it applies to.
        #[arg(long, default_value = "")]
        platform: String,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Declare that you rebuilt image `image` and got measurement `measurement`.
    Reproduce {
        /// Account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// Image id.
        #[arg(long)]
        image: u64,
        /// Measurement hash.
        #[arg(long)]
        measurement: String,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// List registered images, their measurements and how many others reproduced each.
    List {
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
}

/// Runs `boltchain image`.
pub fn run_image(cmd: ImageCmd) -> Result<()> {
    match cmd {
        ImageCmd::Register { wallet, name, source, build, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IImageRegistry::registerCall {
                name: name.clone(),
                source: source.into_bytes().into(),
                build,
            }
            .abi_encode();
            let hash = send_tx(&url, &s, IMAGES, U256::ZERO, data.into())?;
            let id = first_topic(&url, hash, "ImageRegistered(uint64,address,string,bytes)")?;
            println!("image {id} registered: {name}");
        }
        ImageCmd::Measure { wallet, image, kind, tdx, evidence, simulate, platform, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let kind = parse_kind(&kind)?;
            let raw = if simulate {
                sim_measurement(kind)
            } else if kind == TDX {
                let h = tdx.context("--tdx MRTD‖RTMR0‖RTMR1‖RTMR2 (hex) is required")?;
                let b = hex::decode(h.trim_start_matches("0x"))?;
                if b.len() != 192 {
                    bail!("--tdx takes 192 bytes (MRTD and RTMR0–2, 48 bytes each)");
                }
                b
            } else {
                let f = evidence.context("--evidence FILE is required for TPM measurements")?;
                let ev = Evidence::from_bytes(&std::fs::read(f)?)?;
                let q = tpm::Quote::parse(&ev.quote)?;
                let (pcrs, _) = tpm::replay(&ev.event_log)?;
                tpm::measurement_bytes(q.pcr_mask, &tpm::selected(&pcrs, q.pcr_mask))
            };
            let m = keccak256(&raw);
            let data =
                IImageRegistry::addMeasurementCall { id: image, kind, raw: raw.into(), platform }
                    .abi_encode();
            send_tx(&url, &s, IMAGES, U256::ZERO, data.into())?;
            println!("image {image}: {} measurement {m} added", kind_name(kind));
        }
        ImageCmd::Reproduce { wallet, image, measurement, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data =
                IImageRegistry::reproduceCall { id: image, m: hex32(&measurement)? }.abi_encode();
            send_tx(&url, &s, IMAGES, U256::ZERO, data.into())?;
            println!("recorded: you reproduced image {image}");
        }
        ImageCmd::List { rpc: url } => {
            let n = call(&url, IMAGES, IImageRegistry::imageCountCall {})?.to::<u64>();
            if n == 0 {
                println!("no images registered");
            }
            for id in 1..=n {
                let i = call(&url, IMAGES, IImageRegistry::imageCall { id })?;
                println!(
                    "{id}: {} — source {} — by {}",
                    i.name,
                    String::from_utf8_lossy(&i.source),
                    i.registrant
                );
                if !i.build.is_empty() {
                    println!("    build: {}", i.build);
                }
                for m in call(&url, IMAGES, IImageRegistry::measurementsOfCall { id })? {
                    let d = call(&url, IMAGES, IImageRegistry::measurementCall { id, m })?;
                    println!(
                        "    {} {m} — {} — reproduced by {} other(s)",
                        kind_name(d.kind),
                        if d.platform.is_empty() { "any platform" } else { &d.platform },
                        d.reproductions
                    );
                }
            }
        }
    }
    Ok(())
}

// ===================================================================== collateral

/// Intel collateral documents to submit.
#[derive(Debug, Clone, Default)]
pub struct CollateralSet {
    /// CA certificates under the root (DER).
    pub cas: Vec<Vec<u8>>,
    /// CRLs (DER).
    pub crls: Vec<Vec<u8>>,
    /// TDX TCB info documents (JSON).
    pub tcb_infos: Vec<String>,
    /// TD_QE identity (JSON).
    pub qe_identity: Option<String>,
}

impl CollateralSet {
    /// The simulated PKI's collateral (development chains).
    pub fn simulated() -> Self {
        let c = SimIntel::dev().collateral();
        Self {
            cas: c.cas,
            crls: c.crls,
            tcb_infos: vec![c.tcb_info],
            qe_identity: Some(c.qe_identity),
        }
    }

    /// Reads files saved from Intel's PCS: `*.der` certificates and CRLs (told apart by
    /// content), `tcb-info*.json`, `qe-identity.json`.
    pub fn from_dir(dir: &std::path::Path) -> Result<Self> {
        let mut out = Self::default();
        let mut names: Vec<PathBuf> =
            std::fs::read_dir(dir)?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        names.sort();
        for p in names {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            let b = std::fs::read(&p)?;
            if n.ends_with(".der") {
                if bolt_attest::der::Cert::parse(&b).is_ok() {
                    // The root itself is compiled into the contract.
                    if !n.starts_with("root-ca.") {
                        out.cas.push(b);
                    }
                } else if bolt_attest::der::Crl::parse(&b).is_ok() {
                    out.crls.push(b);
                }
            } else if n.starts_with("tcb-info") && n.ends_with(".json") {
                out.tcb_infos.push(String::from_utf8(b)?);
            } else if n.starts_with("qe-identity") && n.ends_with(".json") {
                out.qe_identity = Some(String::from_utf8(b)?);
            }
        }
        Ok(out)
    }

    /// Fetches the current documents from Intel's PCS for the given FMSPCs.
    pub fn fetch_intel(fmspcs: &[String]) -> Result<Self> {
        const PCS: &str = "https://api.trustedservices.intel.com";
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .try_proxy_from_env(true)
            .build();
        let get = |url: &str, header: Option<&str>| -> Result<(Vec<u8>, Option<String>)> {
            let r = agent.get(url).call().with_context(|| format!("GET {url}"))?;
            let h = header.and_then(|n| r.header(n).map(str::to_string));
            let mut b = Vec::new();
            r.into_reader().take(16 << 20).read_to_end(&mut b)?;
            Ok((b, h))
        };
        let mut out = Self::default();
        let chain_of = |h: Option<String>| -> Result<Vec<Vec<u8>>> {
            let pem = percent_decode(&h.context("no issuer chain header")?);
            Ok(bolt_attest::der::pem_certs(pem.as_bytes())?)
        };
        let (root_crl, _) =
            get("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der", None)?;
        out.crls.push(root_crl);
        for ca in ["platform", "processor"] {
            let (crl, h) = get(
                &format!("{PCS}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der"),
                Some("SGX-PCK-CRL-Issuer-Chain"),
            )?;
            for c in chain_of(h)? {
                if !out.cas.contains(&c) {
                    out.cas.push(c);
                }
            }
            out.crls.push(crl);
        }
        for f in fmspcs {
            let (doc, h) = get(
                &format!("{PCS}/tdx/certification/v4/tcb?fmspc={f}"),
                Some("TCB-Info-Issuer-Chain"),
            )?;
            for c in chain_of(h)? {
                if !out.cas.contains(&c) {
                    out.cas.push(c);
                }
            }
            out.tcb_infos.push(String::from_utf8(doc)?);
        }
        let (qe, _) = get(&format!("{PCS}/tdx/certification/v4/qe/identity"), None)?;
        out.qe_identity = Some(String::from_utf8(qe)?);
        // The root's own certificate is in the chains; the contract has its key.
        out.cas.retain(|c| {
            bolt_attest::der::Cert::parse(c).map(|x| x.subject != x.issuer).unwrap_or(false)
        });
        Ok(out)
    }

    /// A local [`Collateral`] under `root` with everything that verifies at `now`.
    pub fn local(&self, root: bolt_attest::Point, now: u64) -> Collateral {
        let mut c = Collateral::with_root(root);
        for ca in &self.cas {
            let _ = c.add_ca(ca, now);
        }
        for crl in &self.crls {
            let _ = c.add_crl(crl);
        }
        for t in &self.tcb_infos {
            let _ = c.set_tcb_info(t, now);
        }
        if let Some(q) = &self.qe_identity {
            let _ = c.set_qe_identity(q, now);
        }
        c
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Submits whatever in `set` the chain does not have yet (each call is simulated first;
/// documents that are not newer are skipped). Returns how many were submitted.
pub fn submit_collateral(url: &str, s: &PrivateKeySigner, set: &CollateralSet) -> Result<usize> {
    let now = unix_now();
    let mut sent = 0;
    let mut try_send = |what: String, data: Vec<u8>| -> Result<()> {
        let est = rpc(
            url,
            "eth_estimateGas",
            json!([{"from": s.address(), "to": COLLATERAL, "data": hex::encode_prefixed(&data)}, "latest"]),
        );
        if let Err(e) = est {
            // Already there, not newer, or not valid now.
            eprintln!("skipped {what}: {e:#}");
            return Ok(());
        }
        send_tx(url, s, COLLATERAL, U256::ZERO, data.into())?;
        println!("submitted {what}");
        sent += 1;
        Ok(())
    };
    // CRLs from the root first (they may revoke a CA), then CAs, then the CAs' CRLs.
    let root = call(url, COLLATERAL, ITeeCollateral::rootCall {})?;
    // The CAs alone: a document's signer is the CA whose key verifies it.
    let local = CollateralSet { cas: set.cas.clone(), ..Default::default() }
        .local((root.x.0, root.y.0), now);
    for crl in &set.crls {
        try_send(
            "CRL".into(),
            ITeeCollateral::setCrlCall { der: crl.clone().into() }.abi_encode(),
        )?;
    }
    for ca in &set.cas {
        let c = bolt_attest::der::Cert::parse(ca)?;
        let have = call(url, COLLATERAL, ITeeCollateral::casCall { subject: c.subject })?;
        if have.x == B256::ZERO {
            try_send(
                "CA certificate".into(),
                ITeeCollateral::addCaCall { der: ca.clone().into() }.abi_encode(),
            )?;
        }
    }
    for crl in &set.crls {
        try_send(
            "CRL".into(),
            ITeeCollateral::setCrlCall { der: crl.clone().into() }.abi_encode(),
        )?;
    }
    // The signer of a document is the CA whose key verifies it.
    let signer_of = |doc: &str, tcb: bool| -> Option<B256> {
        let mut c = local.clone();
        if tcb {
            c.set_tcb_info(doc, now).ok().map(|(_, s)| s)
        } else {
            c.set_qe_identity(doc, now).ok()
        }
    };
    for t in &set.tcb_infos {
        let Some(signer) = signer_of(t, true) else { continue };
        try_send(
            "TCB info".into(),
            ITeeCollateral::setTcbInfoCall { document: t.clone().into_bytes().into(), signer }
                .abi_encode(),
        )?;
    }
    if let Some(q) = &set.qe_identity
        && let Some(signer) = signer_of(q, false)
    {
        try_send(
            "QE identity".into(),
            ITeeCollateral::setQeIdentityCall { document: q.clone().into_bytes().into(), signer }
                .abi_encode(),
        )?;
    }
    Ok(sent)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `boltchain collateral`.
#[derive(Debug, clap::Subcommand)]
pub enum CollateralCmd {
    /// Submit Intel's current collateral (anyone may: Intel signed it). Fetches from Intel's PCS
    /// unless `--dir` or `--simulated` is given; skips documents the chain already has.
    Update {
        /// Account key file (pays the gas).
        #[arg(long)]
        wallet: PathBuf,
        /// FMSPCs whose TDX TCB info to fetch (hex), e.g. 00806F050000.
        #[arg(long, value_delimiter = ',', default_value = "00806F050000")]
        fmspc: Vec<String>,
        /// Read the documents from this directory instead of fetching them.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Submit the simulated PKI's collateral (development chains).
        #[arg(long)]
        simulated: bool,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Show the collateral in force.
    Show {
        /// FMSPC (hex).
        #[arg(long, default_value = "00806F050000")]
        fmspc: String,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
}

/// Runs `boltchain collateral`.
pub fn run_collateral(cmd: CollateralCmd) -> Result<()> {
    match cmd {
        CollateralCmd::Update { wallet, fmspc, dir, simulated, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let set = if simulated {
                CollateralSet::simulated()
            } else if let Some(d) = dir {
                CollateralSet::from_dir(&d)?
            } else {
                CollateralSet::fetch_intel(&fmspc)?
            };
            let n = submit_collateral(&url, &s, &set)?;
            println!("{n} document(s) submitted");
        }
        CollateralCmd::Show { fmspc, rpc: url } => {
            let r = call(&url, COLLATERAL, ITeeCollateral::rootCall {})?;
            let intel = r.x.0 == bolt_attest::intel::INTEL_ROOT.0;
            println!(
                "root: {}",
                if intel { "Intel SGX Root CA" } else { "simulated (development chain)" }
            );
            let f: [u8; 6] =
                hex::decode(&fmspc)?.try_into().map_err(|_| anyhow::anyhow!("FMSPC is 6 bytes"))?;
            let t = call(&url, COLLATERAL, ITeeCollateral::tcbInfoCall { fmspc: f.into() })?;
            if t.info.evaluation == 0 {
                println!("TCB info for {fmspc}: none");
            } else {
                println!(
                    "TCB info for {fmspc}: evaluation {}, next update {}, {} level(s)",
                    t.info.evaluation,
                    t.info.nextUpdate,
                    t.levels.len()
                );
            }
            let q = call(&url, COLLATERAL, ITeeCollateral::qeIdentityCall {})?;
            println!("QE identity: evaluation {}, next update {}", q.evaluation, q.nextUpdate);
        }
    }
    Ok(())
}

// ===================================================================== enclave (operator)

/// How an action reaches the chain: from a wallet, or through a relay (no BOLT needed).
#[derive(Debug, Clone, clap::Args)]
pub struct Submit {
    /// Account key file that pays the gas.
    #[arg(long)]
    pub wallet: Option<PathBuf>,
    /// Relay endpoint (`bolt_relay`) instead of a wallet.
    #[arg(long)]
    pub relay: Option<String>,
}

impl Submit {
    fn send(&self, url: &str, to: Address, data: Vec<u8>) -> Result<B256> {
        if let Some(w) = &self.wallet {
            return send_tx(url, &load_wallet(w)?, to, U256::ZERO, data.into());
        }
        let r = self.relay.as_deref().unwrap_or(url);
        through_relay(r, to, data)
    }
}

/// `boltchain enclave`.
#[derive(Debug, clap::Subcommand)]
pub enum EnclaveCmd {
    /// Register this machine with an attestation from its runtime (one operator per machine).
    Register {
        /// Account key file (the operator).
        #[arg(long)]
        wallet: PathBuf,
        /// The runtime's control endpoint (`enclave runtime`).
        #[arg(long, default_value = "http://127.0.0.1:9100")]
        runtime: String,
        /// Endpoint the verifier panel and renters reach the runtime at (default: --runtime).
        #[arg(long)]
        endpoint: Option<String>,
        /// CPU cores offered.
        #[arg(long, default_value_t = 4)]
        cpus: u32,
        /// Memory offered, GiB.
        #[arg(long, default_value_t = 16)]
        mem: u32,
        /// GPU, if any.
        #[arg(long, default_value = "")]
        gpu: String,
        /// Hourly price, BOLT (offers the machine right away).
        #[arg(long)]
        price: Option<String>,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Set a machine's hourly price and availability.
    Offer {
        /// Account key file (the operator).
        #[arg(long)]
        wallet: PathBuf,
        /// Machine id.
        #[arg(long)]
        machine: u64,
        /// Hourly price, BOLT.
        #[arg(long)]
        price: String,
        /// Stop taking new leases.
        #[arg(long)]
        unavailable: bool,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Deposit, unbond or claim the operator bond.
    Bond {
        /// Account key file (the operator).
        #[arg(long)]
        wallet: PathBuf,
        /// deposit, unbond or claim.
        action: String,
        /// Amount, BOLT (deposit, unbond).
        amount: Option<String>,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Start lease `lease` in the runtime and submit its attestation.
    Activate {
        /// Lease id.
        #[arg(long)]
        lease: u64,
        /// The runtime's control endpoint.
        #[arg(long, default_value = "http://127.0.0.1:9100")]
        runtime: String,
        #[command(flatten)]
        submit: Submit,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Announce leaving a lease (after the notice period).
    Exit {
        /// Account key file (the operator).
        #[arg(long)]
        wallet: PathBuf,
        /// Lease id.
        #[arg(long)]
        lease: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// List registered machines.
    Machines {
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Run an agent runtime. Only `--simulate` exists yet: a simulated TDX or TPM machine for
    /// development chains (the real `bolt-art` images need the hardware).
    Runtime(RuntimeArgs),
    /// Withdraw earnings (and relay fees, refunds) held by EnclaveLease.
    Withdraw {
        /// Account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
}

/// Runs `boltchain enclave`.
pub fn run_enclave(cmd: EnclaveCmd) -> Result<()> {
    match cmd {
        EnclaveCmd::Register { wallet, runtime, endpoint, cpus, mem, gpu, price, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let r = runtime_get(&runtime, &format!("/attest/machine?operator={}", s.address()))?;
            let kind = r["kind"].as_u64().context("kind")? as u8;
            let att = hex::decode(r["attestation"].as_str().context("attestation")?)?;
            let data = IEnclaveLease::registerMachineCall {
                kind,
                attestation: att.into(),
                endpoint: endpoint.unwrap_or(runtime),
                cpus,
                memGiB: mem,
                gpu,
            }
            .abi_encode();
            let hash = send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
            let m = first_topic(&url, hash, "MachineRegistered(uint64,address,uint8,bytes32)")?
                .to::<u64>();
            if kind == TDX {
                println!("machine {m} registered and verified (TDX quote checked on chain)");
            } else {
                println!("machine {m} registered; the verifier panel will check its TPM evidence");
            }
            if let Some(p) = price {
                let data = IEnclaveLease::setOfferCall {
                    m,
                    pricePerHour: parse_bolt(&p)?.to::<u128>(),
                    available: true,
                }
                .abi_encode();
                send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
                println!("offered at {p} BOLT/hour");
            }
        }
        EnclaveCmd::Offer { wallet, machine, price, unavailable, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IEnclaveLease::setOfferCall {
                m: machine,
                pricePerHour: parse_bolt(&price)?.to::<u128>(),
                available: !unavailable,
            }
            .abi_encode();
            send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
            println!(
                "machine {machine}: {price} BOLT/hour, {}",
                if unavailable { "not taking leases" } else { "available" }
            );
        }
        EnclaveCmd::Bond { wallet, action, amount, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let amt = || -> Result<U256> { parse_bolt(amount.as_deref().context("amount")?) };
            let (value, data) = match action.as_str() {
                "deposit" => (amt()?, IEnclaveLease::depositBondCall {}.abi_encode()),
                "unbond" => (U256::ZERO, IEnclaveLease::unbondCall { amount: amt()? }.abi_encode()),
                "claim" => (U256::ZERO, IEnclaveLease::claimUnbondedCall {}.abi_encode()),
                _ => bail!("action is deposit, unbond or claim"),
            };
            send_tx(&url, &s, LEASES, value, data.into())?;
            let o = call(&url, LEASES, IEnclaveLease::operatorsCall { operator: s.address() })?;
            println!(
                "bond {} BOLT, unbonding {} BOLT",
                format_bolt(o.bond),
                format_bolt(o.unbonding)
            );
        }
        EnclaveCmd::Activate { lease, runtime, submit, rpc: url } => {
            let r = runtime_post(&runtime, "/lease/start", &json!({"lease": lease}))?;
            let signer: Address = r["signer"].as_str().context("signer")?.parse()?;
            let enc = hex32(r["encKey"].as_str().context("encKey")?)?;
            let att = hex::decode(r["attestation"].as_str().context("attestation")?)?;
            let data = IEnclaveLease::activateCall {
                id: U256::from(lease),
                signer,
                encKey: enc,
                attestation: att.into(),
            }
            .abi_encode();
            submit.send(&url, LEASES, data)?;
            let l = call(&url, LEASES, IEnclaveLease::leaseCall { id: U256::from(lease) })?;
            println!("lease {lease}: {} (enclave key {signer})", state::name(l.state));
        }
        EnclaveCmd::Exit { wallet, lease, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IEnclaveLease::exitCall { id: U256::from(lease) }.abi_encode();
            send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
            println!("exit announced for lease {lease}");
        }
        EnclaveCmd::Machines { rpc: url } => print_machines(&url, false)?,
        EnclaveCmd::Runtime(a) => run_runtime(a)?,
        EnclaveCmd::Withdraw { wallet, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let b = call(&url, LEASES, IEnclaveLease::balanceOfCall { account: s.address() })?;
            if b.is_zero() {
                println!("nothing to withdraw");
                return Ok(());
            }
            let data = IEnclaveLease::withdrawCall { to: s.address() }.abi_encode();
            send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
            println!("withdrew {} BOLT", format_bolt(b));
        }
    }
    Ok(())
}

fn print_machines(url: &str, offers_only: bool) -> Result<()> {
    let n = call(url, LEASES, IEnclaveLease::machineCountCall {})?.to::<u64>();
    let mut shown = 0;
    for m in 1..=n {
        let mc = call(url, LEASES, IEnclaveLease::machineCall { m })?;
        let black = call(url, LEASES, IEnclaveLease::blacklistedCall { machineId: mc.machineId })?;
        if offers_only && (!mc.verified || !mc.available || black || mc.pricePerHour == 0) {
            continue;
        }
        let o = call(url, LEASES, IEnclaveLease::operatorsCall { operator: mc.operator })?;
        shown += 1;
        println!(
            "machine {m}: {} — {} cores, {} GiB{} — {} BOLT/hour — operator {} (bond {} BOLT) — {}{}{}",
            kind_name(mc.kind),
            mc.cpus,
            mc.memGiB,
            if mc.gpu.is_empty() { String::new() } else { format!(", {}", mc.gpu) },
            format_bolt(U256::from(mc.pricePerHour)),
            mc.operator,
            format_bolt(o.bond),
            if mc.verified { "verified" } else { "awaiting the panel" },
            if mc.kind == TDX && mc.verified {
                format!(", TCB {}", tcb_name(mc.tcbStatus))
            } else {
                String::new()
            },
            if black { " — BLACKLISTED" } else { "" },
        );
        println!(
            "    machine id {} — {} active lease(s) — {}",
            mc.machineId, mc.leases, mc.endpoint
        );
    }
    if shown == 0 {
        println!("{}", if offers_only { "no machines on offer" } else { "no machines registered" });
    }
    Ok(())
}

fn runtime_get(base: &str, path: &str) -> Result<Value> {
    let (code, body) = http(
        "GET",
        &format!("{}{path}", base.trim_end_matches('/')),
        None,
        Duration::from_secs(60),
    )?;
    if code != 200 {
        bail!("runtime: HTTP {code}: {}", String::from_utf8_lossy(&body));
    }
    Ok(serde_json::from_slice(&body)?)
}

fn runtime_post(base: &str, path: &str, body: &Value) -> Result<Value> {
    let b = body.to_string();
    let (code, out) = http(
        "POST",
        &format!("{}{path}", base.trim_end_matches('/')),
        Some(b.as_bytes()),
        Duration::from_secs(60),
    )?;
    if code != 200 {
        bail!("runtime: HTTP {code}: {}", String::from_utf8_lossy(&out));
    }
    Ok(serde_json::from_slice(&out)?)
}

// ===================================================================== simulated runtime

/// `boltchain enclave runtime`.
#[derive(Debug, Clone, clap::Args)]
pub struct RuntimeArgs {
    /// Simulate the hardware (development chains only: their genesis trusts the simulated
    /// Intel root, and their verifier panels the simulated TPM vendor).
    #[arg(long)]
    pub simulate: bool,
    /// tdx or tpm.
    #[arg(long, default_value = "tdx")]
    pub kind: String,
    /// Control and attestation endpoint.
    #[arg(long, default_value = "127.0.0.1:9100")]
    pub listen: String,
    /// Machine identity seed (same seed, same simulated machine).
    #[arg(long, default_value = "machine-1")]
    pub seed: String,
    /// Where the runtime keeps its (simulated sealed) state: leases, keys, checkpoint versions.
    #[arg(long)]
    pub state: PathBuf,
    /// Seconds between on-chain checkpoints (one hour on real leases).
    #[arg(long, default_value_t = 3600)]
    pub checkpoint_every: u64,
    #[command(flatten)]
    pub submit: Submit,
    /// JSON-RPC endpoint.
    #[arg(long, default_value = RPC)]
    pub rpc: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct LeaseState {
    key: String,
    enc: String,
    version: u64,
    root: String,
    secret_sha256: Option<String>,
    attestation: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct RtState {
    leases: HashMap<u64, LeaseState>,
}

struct Runtime {
    args: RuntimeArgs,
    kind: u8,
    tdx: Option<SimPlatform>,
    tpm: Option<Mutex<SoftTpm>>,
    evidence: Mutex<HashMap<B256, Vec<u8>>>,
    st: Mutex<RtState>,
}

impl Runtime {
    fn save(&self) -> Result<()> {
        let st = self.st.lock();
        let p = self.args.state.join("runtime.json");
        std::fs::write(&p, serde_json::to_vec_pretty(&*st)?)?;
        Ok(())
    }

    /// An attestation bound to `binding` ‖ `second`: a TD quote, or (TPM) the digest of the
    /// evidence now served.
    fn attest(&self, binding: B256, second: B256) -> Vec<u8> {
        if let Some(p) = &self.tdx {
            let mut rd = [0u8; 64];
            rd[..32].copy_from_slice(binding.as_slice());
            rd[32..].copy_from_slice(second.as_slice());
            let rtmr = [SIM_RTMR[0], SIM_RTMR[1], SIM_RTMR[2], [0; 48]];
            return p.quote(&SimPlatform::td_report(SIM_MRTD, rtmr, rd));
        }
        let q = if second == B256::ZERO { binding } else { tpm::activation_data(binding, second) };
        let ev = self.tpm.as_ref().expect("tpm").lock().evidence(tpm::DEFAULT_PCRS, q.as_slice());
        let d = ev.digest();
        self.evidence.lock().insert(d, ev.to_bytes());
        d.to_vec()
    }

    fn handle(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let url = &self.args.rpc;
        let ok = |v: Value| Ok((200, v.to_string().into_bytes()));
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let parts: Vec<&str> = route.trim_matches('/').split('/').collect();
        match (method, parts.as_slice()) {
            ("GET", ["attest", "machine"]) => {
                let op = query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("operator="))
                    .context("operator=")?
                    .parse::<Address>()?;
                let b = call(url, LEASES, IEnclaveLease::machineBindingCall { operator: op })?;
                let att = self.attest(b, B256::ZERO);
                ok(json!({"kind": self.kind, "attestation": hex::encode(att)}))
            }
            ("GET", ["attest", "evidence", h]) => {
                let d = hex32(h)?;
                match self.evidence.lock().get(&d) {
                    Some(b) => Ok((200, b.clone())),
                    None => Ok((404, b"unknown evidence".to_vec())),
                }
            }
            ("POST", ["attest", "challenge"]) => {
                let v: Value = serde_json::from_slice(body)?;
                let blob = hex::decode(v["blob"].as_str().context("blob")?)?;
                let secret = hex::decode(v["secret"].as_str().context("secret")?)?;
                let t = self.tpm.as_ref().context("not a TPM machine")?;
                let c = t.lock().activate_credential(&blob, &secret)?;
                ok(json!({"credential": hex::encode(c)}))
            }
            ("POST", ["lease", "start"]) => {
                let v: Value = serde_json::from_slice(body)?;
                let id = v["lease"].as_u64().context("lease")?;
                let l = call(url, LEASES, IEnclaveLease::leaseCall { id: U256::from(id) })?;
                if l.state != state::PENDING {
                    bail!("lease {id} is {}", state::name(l.state));
                }
                // Fresh keys inside the enclave: the signing key S and the encryption key E.
                let key = PrivateKeySigner::random();
                let (esk, epk) = bolt_vault::SecretKey::generate();
                let enc = B256::from(epk.to_bytes());
                let b = call(
                    url,
                    LEASES,
                    IEnclaveLease::enclaveBindingCall {
                        id: U256::from(id),
                        signer: key.address(),
                        encKey: enc,
                    },
                )?;
                let att = self.attest(b, l.agentHash);
                let prev = self.st.lock().leases.get(&id).map(|p| p.version).unwrap_or(0);
                self.st.lock().leases.insert(
                    id,
                    LeaseState {
                        key: hex::encode(key.to_bytes()),
                        enc: hex::encode(esk.to_bytes()),
                        version: prev.max(l.version),
                        root: hex::encode(l.stateRoot),
                        secret_sha256: None,
                        attestation: hex::encode(&att),
                    },
                );
                self.save()?;
                ok(json!({
                    "signer": key.address(),
                    "encKey": enc,
                    "attestation": hex::encode(att),
                }))
            }
            ("GET", ["lease", id, "attestation"]) => {
                let id: u64 = id.parse()?;
                let st = self.st.lock();
                let l = st.leases.get(&id).context("unknown lease")?;
                let att = hex::decode(&l.attestation)?;
                let body = if self.kind == TDX {
                    json!({"kind": TDX, "quote": l.attestation})
                } else {
                    let d = B256::from_slice(&att);
                    let ev = self.evidence.lock().get(&d).cloned().unwrap_or_default();
                    json!({"kind": TPM, "evidence": hex::encode(ev)})
                };
                ok(body)
            }
            ("POST", ["lease", id, "secret"]) => {
                let id: u64 = id.parse()?;
                let v: Value = serde_json::from_slice(body)?;
                let env = hex::decode(v["envelope"].as_str().context("envelope")?)?;
                let blocks: HashMap<String, String> = serde_json::from_value(v["blocks"].clone())?;
                let sk = {
                    let st = self.st.lock();
                    let l = st.leases.get(&id).context("unknown lease")?;
                    bolt_vault::SecretKey::from_bytes(&hex::decode(&l.enc)?)?
                };
                let get = |c: &bolt_vault::Cid| {
                    blocks.get(&hex::encode(c.0)).and_then(|h| hex::decode(h).ok())
                };
                let (_, data) = bolt_vault::open(&env, &sk, get)?;
                let h = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&data));
                if let Some(l) = self.st.lock().leases.get_mut(&id) {
                    l.secret_sha256 = Some(h.clone());
                }
                self.save()?;
                ok(json!({"sha256": h}))
            }
            ("POST", ["lease", id, "checkpoint"]) => {
                let id: u64 = id.parse()?;
                let v = self.checkpoint(id)?;
                ok(json!({"version": v}))
            }
            ("GET", ["status"]) => {
                let st = self.st.lock();
                let leases: Vec<Value> = st
                    .leases
                    .iter()
                    .map(|(id, l)| json!({"lease": id, "version": l.version, "secret": l.secret_sha256}))
                    .collect();
                ok(json!({"kind": self.kind, "leases": leases}))
            }
            _ => Ok((404, b"not found".to_vec())),
        }
    }

    /// Signs and submits the next checkpoint of lease `id` (if this runtime holds its active
    /// key). Returns the version.
    fn checkpoint(&self, id: u64) -> Result<u64> {
        let url = &self.args.rpc;
        let (key, version, root) = {
            let st = self.st.lock();
            let l = st.leases.get(&id).context("unknown lease")?;
            (PrivateKeySigner::from_slice(&hex::decode(&l.key)?)?, l.version + 1, l.root.clone())
        };
        let active = call(url, LEASES, IEnclaveLease::activeSignerCall { id: U256::from(id) })?;
        if active != key.address() {
            bail!("lease {id}: this runtime's key is not the active enclave");
        }
        // The agent's state advances; a real runtime stores it (encrypted) and puts its CID here.
        let new_root = keccak256([hex::decode(root)?.as_slice(), &version.to_be_bytes()].concat());
        let cid = format!("sim-state:{id}:{version}:{new_root}").into_bytes();
        let head = rpc(url, "eth_blockNumber", json!([]))?;
        let head =
            u64::from_str_radix(head.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
        let seen = head.saturating_sub(1);
        let blk = rpc(url, "eth_getBlockByNumber", json!([format!("0x{seen:x}"), false]))?;
        let seen_hash = hex32(blk["hash"].as_str().context("block hash")?)?;
        let digest = call(
            url,
            LEASES,
            IEnclaveLease::checkpointDigestCall {
                id: U256::from(id),
                version,
                stateRoot: new_root,
                cidHash: keccak256(&cid),
                seenBlockhash: seen_hash,
            },
        )?;
        let sig = key.sign_hash_sync(&digest)?;
        let data = IEnclaveLease::checkpointCall {
            id: U256::from(id),
            version,
            stateCid: cid.into(),
            stateRoot: new_root,
            seenBlock: U256::from(seen),
            sig: sig.as_bytes().to_vec().into(),
        }
        .abi_encode();
        self.args.submit.send(url, LEASES, data)?;
        if let Some(l) = self.st.lock().leases.get_mut(&id) {
            l.version = version;
            l.root = hex::encode(new_root);
        }
        self.save()?;
        tracing::info!(lease = id, version, "checkpoint recorded");
        Ok(version)
    }
}

fn run_runtime(a: RuntimeArgs) -> Result<()> {
    if !a.simulate {
        bail!(
            "only the simulated runtime exists yet (`--simulate`); the bolt-art images for TDX and \
             TPM machines come after the hardware confirmation (ADR 0013 §10)"
        );
    }
    let kind = parse_kind(&a.kind)?;
    std::fs::create_dir_all(&a.state)?;
    let st: RtState = std::fs::read(a.state.join("runtime.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let (tdx, tpm) = if kind == TDX {
        let id = u64::from_be_bytes(keccak256(a.seed.as_bytes())[..8].try_into().unwrap());
        (Some(SimIntel::dev().platform(id)), None)
    } else {
        let mut t = SoftTpm::new(a.seed.as_bytes(), &SimTpmCa::dev());
        t.boot(SIM_TPM_IMAGE);
        (None, Some(Mutex::new(t)))
    };
    let rt = Arc::new(Runtime {
        args: a.clone(),
        kind,
        tdx,
        tpm,
        evidence: Mutex::new(HashMap::new()),
        st: Mutex::new(st),
    });
    let listener =
        TcpListener::bind(&a.listen).with_context(|| format!("listening on {}", a.listen))?;
    println!("simulated {} runtime listening on {}", kind_name(kind), a.listen);
    // Checkpoints.
    let cp = rt.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(cp.args.checkpoint_every.max(1)));
            let ids: Vec<u64> = cp.st.lock().leases.keys().copied().collect();
            for id in ids {
                if let Err(e) = cp.checkpoint(id) {
                    tracing::debug!(lease = id, "checkpoint: {e:#}");
                }
            }
        }
    });
    for conn in listener.incoming() {
        let Ok(s) = conn else { continue };
        let rt = rt.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve(&rt, s) {
                tracing::debug!("runtime request: {e:#}");
            }
        });
    }
    Ok(())
}

fn serve(rt: &Runtime, mut s: TcpStream) -> Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let (head_end, len) = loop {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            bail!("connection closed");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))
                })
                .unwrap_or(0usize);
            break (p + 4, len);
        }
        if buf.len() > 1 << 20 {
            bail!("header too large");
        }
    };
    while buf.len() < head_end + len {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or("/"));
    let body = &buf[head_end..(head_end + len).min(buf.len())];
    let (code, out) =
        rt.handle(method, path, body).unwrap_or_else(|e| (400, format!("{e:#}").into_bytes()));
    write!(
        s,
        "HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if code == 200 { "OK" } else { "Error" },
        out.len()
    )?;
    s.write_all(&out)?;
    Ok(())
}

// ===================================================================== lease (renter)

/// `boltchain lease`.
#[derive(Debug, clap::Subcommand)]
pub enum LeaseCmd {
    /// Machines on offer.
    Offers {
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Rent a machine: escrows `hours` of its price plus relay fees.
    Create {
        /// Account key file (the renter).
        #[arg(long)]
        wallet: PathBuf,
        /// Machine id.
        #[arg(long)]
        machine: u64,
        /// Image id (choose it yourself: the CLI never picks one).
        #[arg(long)]
        image: u64,
        /// The agent package: its keccak256 (hex) or a file to hash.
        #[arg(long)]
        agent: String,
        /// Hours to escrow.
        #[arg(long, default_value_t = 24)]
        hours: u64,
        /// Worst TDX TCB status accepted: 1 up to date … 5 out of date.
        #[arg(long, default_value_t = 1)]
        min_tcb: u8,
        /// Operator bond required, BOLT.
        #[arg(long, default_value = "0")]
        min_bond: String,
        /// Fee per checkpoint for whoever submits it, BOLT.
        #[arg(long, default_value = "0.001")]
        relay_fee: String,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Show a lease.
    Show {
        /// Lease id.
        lease: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Verify the lease's enclave yourself (before giving it secrets): the attestation the
    /// runtime serves, against Intel's collateral fetched independently of the chain.
    Verify {
        /// Lease id.
        lease: u64,
        /// The runtime's endpoint (default: the machine's registered endpoint).
        #[arg(long)]
        runtime: Option<String>,
        /// Collateral from this directory instead of Intel's PCS.
        #[arg(long)]
        collateral: Option<PathBuf>,
        /// The simulated PKI (development chains).
        #[arg(long)]
        simulated: bool,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Hand a secret (API key, state key…) to the enclave, encrypted to its key E.
    Deliver {
        /// Lease id.
        lease: u64,
        /// File holding the secret.
        #[arg(long)]
        file: PathBuf,
        /// The runtime's endpoint (default: the machine's registered endpoint).
        #[arg(long)]
        runtime: Option<String>,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// End a lease (pays up to the last checkpoint; the rest comes back).
    Terminate {
        /// Account key file (the renter).
        #[arg(long)]
        wallet: PathBuf,
        /// Lease id.
        lease: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Move a lease to another machine (pending, degraded, operator leaving or slashed, or
    /// two hours without a checkpoint).
    Migrate {
        /// Account key file (the renter).
        #[arg(long)]
        wallet: PathBuf,
        /// Lease id.
        lease: u64,
        /// New machine id.
        #[arg(long)]
        to: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Add to a lease's escrow.
    TopUp {
        /// Account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// Lease id.
        lease: u64,
        /// Amount, BOLT.
        amount: String,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Re-check a TDX lease's platform against the current collateral (anyone may).
    Recheck {
        /// Account key file (pays the gas).
        #[arg(long)]
        wallet: PathBuf,
        /// Lease id.
        lease: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Give the lease's enclave a limited wallet: this account delegates (EIP-7702) to the
    /// limited-wallet code, and the enclave key may spend within the limits on the targets.
    Wallet {
        /// Account key file (the account the agent spends from).
        #[arg(long)]
        wallet: PathBuf,
        /// Lease id (0 revokes).
        #[arg(long)]
        lease: u64,
        /// Daily limit, BOLT.
        #[arg(long, default_value = "1")]
        daily: String,
        /// Per-transaction limit, BOLT.
        #[arg(long, default_value = "0.1")]
        per_tx: String,
        /// Contracts or accounts it may call.
        #[arg(long, value_delimiter = ',')]
        target: Vec<Address>,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
}

/// Runs `boltchain lease`.
pub fn run_lease(cmd: LeaseCmd) -> Result<()> {
    match cmd {
        LeaseCmd::Offers { rpc: url } => print_machines(&url, true)?,
        LeaseCmd::Create {
            wallet,
            machine,
            image,
            agent,
            hours,
            min_tcb,
            min_bond,
            relay_fee,
            rpc: url,
        } => {
            let s = load_wallet(&wallet)?;
            let mc = call(&url, LEASES, IEnclaveLease::machineCall { m: machine })?;
            let fee = parse_bolt(&relay_fee)?;
            let value =
                U256::from(mc.pricePerHour) * U256::from(hours) + fee * U256::from(hours + 2);
            let data = IEnclaveLease::createLeaseCall {
                m: machine,
                image,
                agentHash: hash_arg(&agent)?,
                minTcb: min_tcb,
                minBond: parse_bolt(&min_bond)?.to::<u128>(),
                relayFee: fee.to::<u128>(),
            }
            .abi_encode();
            let hash = send_tx(&url, &s, LEASES, value, data.into())?;
            let id =
                first_topic(&url, hash, "LeaseCreated(uint256,address,uint64,uint64,bytes32)")?;
            println!(
                "lease {id} created on machine {machine}: {} BOLT escrowed",
                format_bolt(value)
            );
            println!("the operator starts it with `boltchain enclave activate --lease {id}`");
        }
        LeaseCmd::Show { lease, rpc: url } => {
            let l = call(&url, LEASES, IEnclaveLease::leaseCall { id: U256::from(lease) })?;
            println!(
                "lease {lease}: {}{}",
                state::name(l.state),
                if l.degraded { " (degraded)" } else { "" }
            );
            println!("  renter {} — machine {} — image {}", l.renter, l.machine, l.image);
            println!(
                "  {} BOLT/hour — escrow {} BOLT — {} hour(s) paid — relay fee {} BOLT",
                format_bolt(U256::from(l.pricePerHour)),
                format_bolt(U256::from(l.escrow)),
                l.hoursPaid,
                format_bolt(U256::from(l.relayFee))
            );
            println!("  agent {}", l.agentHash);
            if l.signer != Address::ZERO {
                println!("  enclave key {} — encryption key {}", l.signer, l.encKey);
            }
            println!(
                "  checkpoint version {} — state {} — {}",
                l.version,
                l.stateRoot,
                String::from_utf8_lossy(&l.stateCid)
            );
            if l.exitAt != 0 {
                println!("  operator leaves at {}", l.exitAt);
            }
        }
        LeaseCmd::Verify { lease, runtime, collateral, simulated, rpc: url } => {
            verify_lease(&url, lease, runtime, collateral, simulated)?;
        }
        LeaseCmd::Deliver { lease, file, runtime, rpc: url } => {
            let l = call(&url, LEASES, IEnclaveLease::leaseCall { id: U256::from(lease) })?;
            if l.state != state::ACTIVE {
                bail!("lease {lease} is {}", state::name(l.state));
            }
            let base = match runtime {
                Some(r) => r,
                None => call(&url, LEASES, IEnclaveLease::machineCall { m: l.machine })?.endpoint,
            };
            let data = std::fs::read(&file)?;
            let pk = bolt_vault::PublicKey::from_bytes(l.encKey.as_slice())?;
            let sealed = bolt_vault::seal(
                &data,
                "secret",
                "application/octet-stream",
                &[pk],
                &bolt_vault::Options { k: 1, m: 0 },
            )?;
            let mut blocks = serde_json::Map::new();
            for b in std::iter::once(&sealed.manifest).chain(sealed.shards.iter()) {
                blocks.insert(hex::encode(b.cid.0), json!(hex::encode(&b.data)));
            }
            let r = runtime_post(
                &base,
                &format!("/lease/{lease}/secret"),
                &json!({"envelope": hex::encode(&sealed.envelope.data), "blocks": blocks}),
            )?;
            let want = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&data));
            if r["sha256"].as_str() != Some(&want) {
                bail!("the enclave did not confirm the secret");
            }
            println!("secret delivered to lease {lease}'s enclave (sha256 {want})");
        }
        LeaseCmd::Terminate { wallet, lease, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IEnclaveLease::terminateCall { id: U256::from(lease) }.abi_encode();
            send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
            let b = call(&url, LEASES, IEnclaveLease::balanceOfCall { account: s.address() })?;
            println!(
                "lease {lease} ended; {} BOLT to withdraw (`boltchain enclave withdraw`)",
                format_bolt(b)
            );
        }
        LeaseCmd::Migrate { wallet, lease, to, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IEnclaveLease::migrateCall { id: U256::from(lease), to }.abi_encode();
            send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
            println!(
                "lease {lease} moved to machine {to}; it activates when the new enclave attests"
            );
        }
        LeaseCmd::TopUp { wallet, lease, amount, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IEnclaveLease::topUpCall { id: U256::from(lease) }.abi_encode();
            send_tx(&url, &s, LEASES, parse_bolt(&amount)?, data.into())?;
            println!("added {amount} BOLT to lease {lease}");
        }
        LeaseCmd::Recheck { wallet, lease, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IEnclaveLease::recheckCall { id: U256::from(lease) }.abi_encode();
            send_tx(&url, &s, LEASES, U256::ZERO, data.into())?;
            let l = call(&url, LEASES, IEnclaveLease::leaseCall { id: U256::from(lease) })?;
            println!(
                "lease {lease}: {}",
                if l.degraded {
                    "degraded — the renter may migrate"
                } else {
                    "platform acceptable"
                }
            );
        }
        LeaseCmd::Wallet { wallet, lease, daily, per_tx, target, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = if lease == 0 {
                ILimitedWallet::revokeCall {}.abi_encode()
            } else {
                ILimitedWallet::configureCall {
                    lease: U256::from(lease),
                    dailyLimit: parse_bolt(&daily)?.to::<u128>(),
                    perTxLimit: parse_bolt(&per_tx)?.to::<u128>(),
                    targets: target,
                }
                .abi_encode()
            };
            send_delegated(&url, &s, WALLET, data.into())?;
            if lease == 0 {
                println!("{}: the enclave's session key is revoked", s.address());
            } else {
                println!(
                    "{}: lease {lease}'s enclave may spend {daily} BOLT a day, {per_tx} per transaction",
                    s.address()
                );
            }
        }
    }
    Ok(())
}

/// Local verification of a lease's enclave (ADR 0013 §4.3).
fn verify_lease(
    url: &str,
    lease: u64,
    runtime: Option<String>,
    collateral: Option<PathBuf>,
    simulated: bool,
) -> Result<()> {
    let id = U256::from(lease);
    let l = call(url, LEASES, IEnclaveLease::leaseCall { id })?;
    if l.signer == Address::ZERO {
        bail!("lease {lease} has no enclave yet ({})", state::name(l.state));
    }
    let mc = call(url, LEASES, IEnclaveLease::machineCall { m: l.machine })?;
    let base = runtime.unwrap_or(mc.endpoint.clone());
    let r = runtime_get(&base, &format!("/lease/{lease}/attestation"))?;
    let binding = call(
        url,
        LEASES,
        IEnclaveLease::enclaveBindingCall { id, signer: l.signer, encKey: l.encKey },
    )?;
    if mc.kind == TDX {
        let quote = hex::decode(r["quote"].as_str().context("quote")?)?;
        let now = unix_now();
        let (set, root) = if simulated {
            (CollateralSet::simulated(), SimIntel::dev().root_point())
        } else if let Some(d) = collateral {
            (CollateralSet::from_dir(&d)?, bolt_attest::intel::INTEL_ROOT)
        } else {
            // Which FMSPC: read it from the quote's PCK certificate.
            let fmspc = pck_fmspc(&quote)?;
            (
                CollateralSet::fetch_intel(&[hex::encode_upper(fmspc)])?,
                bolt_attest::intel::INTEL_ROOT,
            )
        };
        let col = set.local(root, now);
        let v = tdx::verify(&quote, &col, now)?;
        let check = |ok: bool, what: &str| -> Result<()> {
            if !ok {
                bail!("REFUSE: {what}");
            }
            println!("ok: {what}");
            Ok(())
        };
        println!("quote verifies: TCB {}, QE {}", tcb_name(v.tcb_status), tcb_name(v.qe_status));
        check(v.machine_id == mc.machineId, "the quote comes from the leased machine")?;
        check(
            v.report.report_data[..32] == binding[..],
            "it binds this lease and the enclave keys",
        )?;
        check(v.report.report_data[32..] == l.agentHash[..], "it runs the agent package leased")?;
        let allowed = call(
            url,
            IMAGES,
            IImageRegistry::allowsCall { id: l.image, kind: TDX, m: v.report.measurement() },
        )?;
        check(allowed, "its measurement is registered for the image")?;
        check(v.tcb_status <= l.minTcb, "its TCB is acceptable for the lease")?;
    } else {
        let ev = Evidence::from_bytes(&hex::decode(r["evidence"].as_str().context("evidence")?)?)?;
        let roots = crate::attest::tpm_roots(None, simulated)?;
        let a = tpm::appraise(&ev, &roots, unix_now())?;
        if a.machine_id != mc.machineId
            || a.qualifying_data != tpm::activation_data(binding, l.agentHash).as_slice()
        {
            bail!("REFUSE: the evidence is not bound to this lease and machine");
        }
        if !call(
            url,
            IMAGES,
            IImageRegistry::allowsCall { id: l.image, kind: TPM, m: a.measurement },
        )? {
            bail!("REFUSE: the measurement is not registered for the image");
        }
        println!("ok: TPM evidence (EK certificate, quote, event log) binds this lease and image");
        println!("note: the AK–EK challenge is the verifier panel's; it certified this activation");
    }
    println!("lease {lease}: safe to deliver secrets to encryption key {}", l.encKey);
    Ok(())
}

fn pck_fmspc(quote: &[u8]) -> Result<[u8; 6]> {
    let pem_start = quote
        .windows(27)
        .position(|w| w == b"-----BEGIN CERTIFICATE-----")
        .context("no PCK certificate in the quote")?;
    let certs = bolt_attest::der::pem_certs(&quote[pem_start..])?;
    let pck = bolt_attest::der::Cert::parse(certs.first().context("PCK")?)?;
    Ok(bolt_attest::intel::PckExtension::of(&pck)?.fmspc)
}
