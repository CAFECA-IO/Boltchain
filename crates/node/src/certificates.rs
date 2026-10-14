//! Evidence certificates in the explorer (ADR 0016): uploads for the certificate's storage deal,
//! the deal index, storage quotes and certificate lookups. The `Certificates` contract is an
//! ordinary contract whose address the operator passes with `--certificates`.
//!
//! Uploads are accepted before anything is paid, so they are bounded and collected: a block this
//! node did not have before is deleted again unless a certificate paid for a deal that lists it
//! within [`PAY_WITHIN`].

use crate::explorer::Explorer;
use alloy_primitives::{Address, Bytes, U256, keccak256};
use alloy_sol_types::SolCall;
use bolt_ipld::{Cid, RAW, sha256_cid};
use bolt_store::{RO, StateView, Tx};
use bolt_system::{abi::*, addresses::*};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

/// Largest block accepted (files are cut into 256 KiB pieces; the manifest is small).
pub const MAX_BLOCK: usize = 1 << 20;
/// Largest certificate (all files and the manifest).
pub const MAX_CERT_BYTES: u64 = 256 << 20;
/// Unpaid uploads this node holds at most.
pub const MAX_PENDING_BYTES: u64 = 2 << 30;
/// A deal index must be paid for (a certificate issued) within this time.
pub const PAY_WITHIN: Duration = Duration::from_secs(6 * 3600);
/// Blocks not listed in any deal index are deleted after this time.
pub const LOOSE_FOR: Duration = Duration::from_secs(2 * 3600);
/// Copies kept by SwarmStorage.
pub const REPLICAS: u8 = 3;
/// Storage period asked for: about a year, within SwarmStorage's limit.
pub const KEEP_SECS: u64 = 365 * 86_400;
const MAX_DEAL_EPOCHS: u64 = 3650;

/// Certificate settings of the explorer.
pub struct Certs {
    /// `Certificates` contract.
    pub address: Address,
    /// CAFECA wallet origin (payments).
    pub wallet: String,
    /// Announces a deal index to storage providers (validator nodes); `None` on a devnet.
    pub announce: Option<Arc<dyn Fn(Cid) + Send + Sync>>,
    /// Where upload bookkeeping is kept across restarts.
    pub state_file: Option<PathBuf>,
    state: Mutex<Uploads>,
}

impl std::fmt::Debug for Certs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certs")
            .field("address", &self.address)
            .field("wallet", &self.wallet)
            .finish()
    }
}

/// Upload bookkeeping. Only blocks this node did not already have are tracked (and can be
/// deleted); blocks of paid deals leave the bookkeeping and are kept.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Uploads {
    /// cid -> (size, uploaded at, deal indexes listing it)
    blocks: HashMap<String, (u64, u64, HashSet<String>)>,
    /// deal index root -> (created at, every block of the deal including the index blocks)
    roots: HashMap<String, (u64, Vec<String>)>,
}

impl Uploads {
    fn pending_bytes(&self) -> u64 {
        self.blocks.values().map(|b| b.0).sum()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Certs {
    /// Settings for the contract at `address`; loads upload bookkeeping from `state_file`.
    pub fn new(
        address: Address,
        wallet: String,
        announce: Option<Arc<dyn Fn(Cid) + Send + Sync>>,
        state_file: Option<PathBuf>,
    ) -> Self {
        let state = state_file
            .as_ref()
            .and_then(|f| std::fs::read(f).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self { address, wallet, announce, state_file, state: Mutex::new(state) }
    }

    fn save(&self, st: &Uploads) {
        if let Some(f) = &self.state_file
            && let Ok(b) = serde_json::to_vec(st)
        {
            let tmp = f.with_extension("tmp");
            if std::fs::write(&tmp, b).is_ok() {
                let _ = std::fs::rename(tmp, f);
            }
        }
    }
}

type ApiResult = Result<Value, (u16, String)>;

fn bad(msg: impl Into<String>) -> (u16, String) {
    (400, msg.into())
}

fn internal(e: impl std::fmt::Display) -> (u16, String) {
    (500, e.to_string())
}

// ---------------------------------------------------------------------------------------------
// codes: 10 bytes <-> 16 Crockford base-32 characters
// ---------------------------------------------------------------------------------------------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 10 bytes as 16 Crockford base-32 characters.
pub fn encode_code(code: &[u8; 10]) -> String {
    let v = code.iter().fold(0u128, |a, b| (a << 8) | u128::from(*b));
    (0..16).rev().map(|i| CROCKFORD[((v >> (5 * i)) & 31) as usize] as char).collect()
}

/// Parses a code: 16 Crockford characters, any case, dashes and spaces ignored, I/L read as 1
/// and O as 0.
pub fn decode_code(s: &str) -> Option<[u8; 10]> {
    let mut v = 0u128;
    let mut n = 0;
    for c in s.chars() {
        if c == '-' || c == ' ' {
            continue;
        }
        let c = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        let d = CROCKFORD.iter().position(|x| *x as char == c)?;
        v = (v << 5) | d as u128;
        n += 1;
    }
    if n != 16 {
        return None;
    }
    let mut out = [0u8; 10];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (v >> (8 * (9 - i))) as u8;
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------------------------

impl Explorer {
    fn certs(&self) -> Result<&Certs, (u16, String)> {
        self.certs
            .as_deref()
            .ok_or_else(|| (404, "certificates are not enabled on this node".into()))
    }

    fn view_raw(&self, r: &Tx<'_, RO>, to: Address, data: Vec<u8>) -> Result<Bytes, (u16, String)> {
        let h = self.head_header(r)?;
        let cfg = self.chain.config();
        let input = bolt_exec::BlockInput {
            chain_id: cfg.chain_id,
            number: h.number + 1,
            timestamp: h.timestamp + cfg.slot_seconds,
            beneficiary: h.beneficiary,
            gas_limit: cfg.gas_limit,
            base_fee: 0,
            prevrandao: h.mix_hash,
        };
        bolt_exec::view_call(
            revm::database::WrapDatabaseRef(StateView::latest(r)),
            &input,
            to,
            data.into(),
        )
        .map_err(|e| internal(format!("view call: {e:?}")))
    }

    fn view_on<C: SolCall>(
        &self,
        r: &Tx<'_, RO>,
        to: Address,
        c: C,
    ) -> Result<C::Return, (u16, String)> {
        let out = self.view_raw(r, to, c.abi_encode())?;
        C::abi_decode_returns(&out).map_err(internal)
    }

    /// `POST /api/upload`: blocks as `[u32 big-endian length][bytes]…`; each is stored as a raw
    /// sha-256 block. Returns their CIDs.
    pub(crate) fn upload(&self, body: &[u8]) -> ApiResult {
        let certs = self.certs()?;
        let mut blocks = Vec::new();
        let mut rest = body;
        while !rest.is_empty() {
            if rest.len() < 4 {
                return Err(bad("truncated block length"));
            }
            let n = u32::from_be_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
            if n == 0 || n > MAX_BLOCK || rest.len() < 4 + n {
                return Err(bad("bad block length"));
            }
            blocks.push(&rest[4..4 + n]);
            rest = &rest[4 + n..];
        }
        if blocks.is_empty() {
            return Err(bad("no blocks"));
        }
        let mut st = certs.state.lock();
        let incoming: u64 = blocks.iter().map(|b| b.len() as u64).sum();
        if st.pending_bytes() + incoming > MAX_PENDING_BYTES {
            return Err((503, "this node holds too many unpaid uploads; try again later".into()));
        }
        let w = self.chain.store().writer().map_err(internal)?;
        let t = now();
        let mut cids = Vec::new();
        for b in blocks {
            let cid = sha256_cid(RAW, b);
            let key = cid.to_string();
            if w.ipld(&cid).map_err(internal)?.is_none() {
                w.put_ipld(&cid, b).map_err(internal)?;
                st.blocks.insert(key.clone(), (b.len() as u64, t, HashSet::new()));
            }
            cids.push(key);
        }
        w.commit().map_err(internal)?;
        certs.save(&st);
        Ok(json!({ "cids": cids }))
    }

    /// `POST /api/deal-index` `{ "entry": cid, "blocks": [cid…] }`: builds and stores the
    /// SwarmStorage deal index of blocks this node has (ADR 0014) and announces it. Returns what
    /// `createDeal` needs.
    pub(crate) fn deal_index(&self, body: &[u8]) -> ApiResult {
        #[derive(Deserialize)]
        struct Req {
            entry: String,
            blocks: Vec<String>,
        }
        let certs = self.certs()?;
        let req: Req = serde_json::from_slice(body).map_err(|e| bad(format!("body: {e}")))?;
        if req.blocks.is_empty() || req.blocks.len() > 4096 {
            return Err(bad("1 to 4096 blocks"));
        }
        let entry: Cid = req.entry.parse().map_err(|_| bad("entry: bad CID"))?;
        let r = self.chain.store().reader().map_err(internal)?;
        let mut listed = Vec::new();
        let mut seen = HashSet::new();
        for c in &req.blocks {
            let cid: Cid = c.parse().map_err(|_| bad(format!("bad CID {c}")))?;
            if !seen.insert(cid) {
                continue;
            }
            let b = r
                .ipld(&cid)
                .map_err(internal)?
                .ok_or_else(|| bad(format!("{c} was not uploaded")))?;
            listed.push((cid, b.len() as u64));
        }
        drop(r);
        if !seen.contains(&entry) {
            return Err(bad("entry must be one of the blocks"));
        }
        let total: u64 = listed.iter().map(|(_, n)| n).sum();
        if total > MAX_CERT_BYTES {
            return Err(bad(format!("at most {} MiB per certificate", MAX_CERT_BYTES >> 20)));
        }
        let (root, idx, index_blocks) = bolt_ipld::deal::deal_index(&listed, Some(entry));
        let size = idx.size + index_blocks.iter().map(|(_, b)| b.len() as u64).sum::<u64>();
        let w = self.chain.store().writer().map_err(internal)?;
        let mut st = certs.state.lock();
        let t = now();
        let root_s = root.to_string();
        for (c, b) in &index_blocks {
            if w.ipld(c).map_err(internal)?.is_none() {
                w.put_ipld(c, b).map_err(internal)?;
                st.blocks.insert(c.to_string(), (b.len() as u64, t, HashSet::new()));
            }
        }
        w.commit().map_err(internal)?;
        let all: Vec<String> = listed
            .iter()
            .map(|(c, _)| *c)
            .chain(index_blocks.iter().map(|(c, _)| *c))
            .map(|c| c.to_string())
            .collect();
        for c in &all {
            if let Some(b) = st.blocks.get_mut(c) {
                b.2.insert(root_s.clone());
            }
        }
        st.roots.insert(root_s.clone(), (t, all));
        certs.save(&st);
        drop(st);
        if let Some(a) = &certs.announce {
            a(root);
        }
        Ok(json!({
            "root": root_s,
            "rootBytes": Bytes::from(root.to_bytes()),
            "blocks": idx.count,
            "size": size,
        }))
    }

    /// `GET /api/storage/quote?size=<bytes>`: price, copies, epochs and cost of a certificate's
    /// storage deal from the open SwarmStorage offers.
    pub(crate) fn quote(&self, r: &Tx<'_, RO>, query: &str) -> ApiResult {
        let certs = self.certs()?;
        let size: u64 = crate::explorer::query_param(query, "size")
            .and_then(|v| v.parse().ok())
            .filter(|n| *n > 0 && *n <= MAX_CERT_BYTES + (1 << 20))
            .ok_or_else(|| bad("size: bytes, at most 257 MiB"))?;
        let mib = size.div_ceil(1 << 20);
        let ids = self.view_on(r, SWARM, ISwarmStorage::offerListCall {})?;
        let mut prices = Vec::new();
        for id in ids {
            let o = self.view_on(r, SWARM, ISwarmStorage::offerCall { id })?;
            if o.open && o.capacityMiB >= o.usedMiB + mib {
                prices.push(o.minPrice);
            }
        }
        prices.sort_unstable();
        if prices.is_empty() {
            return Err((503, "no storage provider offers space right now".into()));
        }
        let replicas = (prices.len() as u8).min(REPLICAS);
        let price = prices[replicas as usize - 1];
        let rules = self.chain.rules();
        let epoch_secs = rules.epoch_slots * self.chain.config().slot_seconds;
        let epochs = KEEP_SECS.div_ceil(epoch_secs.max(1)).clamp(1, MAX_DEAL_EPOCHS);
        let per_epoch = (U256::from(price) * U256::from(mib) + U256::from(1023)) / U256::from(1024);
        let cost = per_epoch * U256::from(replicas) * U256::from(epochs);
        let head = self.head_header(r)?;
        Ok(json!({
            "contract": certs.address,
            "size": size,
            "mib": mib,
            "replicas": replicas,
            "offers": prices.len(),
            "epochs": epochs,
            "price": price.to_string(),
            "cost": cost.to_string(),
            "until": head.timestamp + epochs * epoch_secs,
        }))
    }

    /// `GET /api/cert/<code>`: a certificate and its storage deal (as the contract reports them;
    /// the page checks the `Issued` event against the block hash itself).
    pub(crate) fn certificate(&self, r: &Tx<'_, RO>, code: &str) -> ApiResult {
        let certs = self.certs()?;
        let raw = decode_code(code).ok_or_else(|| bad("a code is 16 letters and digits"))?;
        let c =
            self.view_on(r, certs.address, ICertificates::certificateCall { code: raw.into() })?;
        if c.issuer == Address::ZERO {
            return Err((404, "no certificate with this code".into()));
        }
        let d = self.view_on(r, SWARM, ISwarmStorage::dealCall { id: c.deal })?;
        let manifest = Cid::try_from(c.manifest.as_ref()).map(|c| c.to_string()).ok();
        let deal_root = Cid::try_from(d.root.as_ref()).map(|c| c.to_string()).ok();
        let rules = self.chain.rules();
        let head = self.head_header(r)?;
        Ok(json!({
            "code": encode_code(&raw),
            "codeHex": Bytes::from(raw.to_vec()),
            "contract": certs.address,
            "issuer": c.issuer,
            "issuedAt": c.issuedAt,
            "block": c.blockNumber,
            "files": c.files,
            "public": c.publicFiles,
            "root": c.root,
            "manifest": manifest,
            "deal": {
                "id": c.deal.to_string(),
                "root": deal_root,
                "replicas": d.replicas,
                "startEpoch": d.startEpoch,
                "endEpoch": d.endEpoch,
                "closed": d.closed,
                "epoch": rules.epoch_of(head.number + 1),
                "epochSeconds": rules.epoch_slots * self.chain.config().slot_seconds,
            },
        }))
    }
}

/// Deletes unpaid uploads (see the module notes). Runs every ten minutes.
pub fn spawn_collector(ex: Arc<Explorer>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(600));
            if let Err(e) = collect(&ex) {
                tracing::warn!("certificate uploads: {e:?}");
            }
        }
    });
}

/// One collection pass: paid deal indexes leave the bookkeeping (their blocks are kept), unpaid
/// ones expire after [`PAY_WITHIN`], and blocks no pending index lists are deleted after
/// [`LOOSE_FOR`].
pub fn collect(ex: &Explorer) -> Result<usize, (u16, String)> {
    let certs = ex.certs()?;
    let t = now();
    let r = ex.chain.store().reader().map_err(internal)?;
    let roots: Vec<(String, u64)> =
        certs.state.lock().roots.iter().map(|(k, v)| (k.clone(), v.0)).collect();
    let mut paid = Vec::new();
    let mut expired = Vec::new();
    for (root, created) in roots {
        let cid: Cid = match root.parse() {
            Ok(c) => c,
            Err(_) => {
                expired.push(root);
                continue;
            }
        };
        let code = ex.view_on(
            &r,
            certs.address,
            ICertificates::codeOfDealCall { dealRootHash: keccak256(cid.to_bytes()) },
        )?;
        if code != alloy_primitives::FixedBytes::ZERO {
            paid.push(root);
        } else if created + PAY_WITHIN.as_secs() < t {
            expired.push(root);
        }
    }
    drop(r);
    let mut st = certs.state.lock();
    for root in &paid {
        if let Some((_, cids)) = st.roots.remove(root) {
            for c in cids {
                st.blocks.remove(&c);
            }
        }
    }
    for root in &expired {
        if let Some((_, cids)) = st.roots.remove(root) {
            for c in cids {
                if let Some(b) = st.blocks.get_mut(&c) {
                    b.2.remove(root);
                }
            }
        }
    }
    let doomed: Vec<String> = st
        .blocks
        .iter()
        .filter(|(_, (_, at, roots))| roots.is_empty() && at + LOOSE_FOR.as_secs() < t)
        .map(|(c, _)| c.clone())
        .collect();
    if !doomed.is_empty() {
        let w = ex.chain.store().writer().map_err(internal)?;
        for c in &doomed {
            if let Ok(cid) = c.parse::<Cid>() {
                w.del_ipld(&cid).map_err(internal)?;
            }
        }
        w.commit().map_err(internal)?;
        for c in &doomed {
            st.blocks.remove(c);
        }
    }
    certs.save(&st);
    if !doomed.is_empty() || !paid.is_empty() {
        tracing::info!(
            paid = paid.len(),
            expired = expired.len(),
            deleted = doomed.len(),
            "certificate uploads"
        );
    }
    Ok(doomed.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use alloy_sol_types::SolValue;
    use bolt_chain::Chain;

    const CERTS: Address = Address::new([0xce; 20]);

    fn body(blocks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for b in blocks {
            out.extend((b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
        out
    }

    fn post(ex: &Explorer, path: &str, body: &[u8]) -> (u16, Value) {
        let (s, _, b) =
            ex.respond(&format!("POST {path} HTTP/1.1\r\n\r\n"), body).expect("handled");
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn get(ex: &Explorer, path: &str) -> (u16, Value) {
        let (s, _, b) = ex.respond(&format!("GET {path} HTTP/1.1\r\n\r\n"), &[]).expect("handled");
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    /// A dev chain with the Certificates contract, where the deal index `paid` counts as paid
    /// (its `codeOfDeal` entry is set).
    fn explorer(dir: &std::path::Path, paid: Option<Cid>) -> Explorer {
        let mut g =
            bolt_primitives::Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap();
        let mut storage = std::collections::BTreeMap::new();
        if let Some(root) = paid {
            let slot = keccak256((keccak256(root.to_bytes()), U256::from(1)).abi_encode());
            storage.insert(slot, B256::repeat_byte(0xff));
        }
        g.alloc.insert(
            CERTS,
            bolt_primitives::genesis::GenesisAccount {
                code: bolt_system::artifacts::certificates().deployed.clone(),
                storage,
                ..Default::default()
            },
        );
        let chain = Arc::new(Chain::open(dir.join("chain"), &g).unwrap());
        let certs =
            Certs::new(CERTS, "https://cafeca.io".into(), None, Some(dir.join("uploads.json")));
        Explorer { chain, pool: None, certs: Some(Arc::new(certs)), host: None }
    }

    fn age(ex: &Explorer, secs: u64) {
        let mut st = ex.certs.as_ref().unwrap().state.lock();
        for b in st.blocks.values_mut() {
            b.1 -= secs;
        }
        for r in st.roots.values_mut() {
            r.0 -= secs;
        }
    }

    #[test]
    fn uploads_deal_index_and_collection() {
        let d = tempfile::tempdir().unwrap();
        let (a, b, c) = (vec![1u8; 300_000], vec![2u8; 1000], b"{\"v\":1}".to_vec());
        let cids: Vec<Cid> = [&a, &b, &c].iter().map(|x| sha256_cid(RAW, x)).collect();
        // The deal index the handler will build, so the test chain can mark it as paid.
        let listed: Vec<(Cid, u64)> = vec![(cids[2], c.len() as u64), (cids[0], a.len() as u64)];
        let (paid_root, _, _) = bolt_ipld::deal::deal_index(&listed, Some(cids[2]));
        let ex = explorer(d.path(), Some(paid_root));

        // Uploads: CIDs of raw blocks; malformed bodies are refused.
        let (s, v) = post(&ex, "/api/upload", &body(&[&a, &b, &c]));
        assert_eq!(s, 200, "{v}");
        let got: Vec<String> = serde_json::from_value(v["cids"].clone()).unwrap();
        assert_eq!(got, cids.iter().map(|c| c.to_string()).collect::<Vec<_>>());
        assert_eq!(post(&ex, "/api/upload", &[0, 0, 0, 9, 1]).0, 400);
        assert_eq!(post(&ex, "/api/upload", &[]).0, 400);
        let big = vec![0u8; MAX_BLOCK + 1];
        assert_eq!(post(&ex, "/api/upload", &body(&[&big])).0, 400);
        assert_eq!(post(&ex, "/api/nope", b"x").0, 405);

        // Deal index over c (entry) and a: what createDeal needs.
        let req = json!({ "entry": cids[2].to_string(), "blocks": [cids[2].to_string(), cids[0].to_string()] });
        let (s, v) = post(&ex, "/api/deal-index", req.to_string().as_bytes());
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["root"], paid_root.to_string());
        assert_eq!(v["blocks"], 2);
        assert!(v["size"].as_u64().unwrap() > (a.len() + c.len()) as u64);
        // A second, unpaid deal index over b.
        let req2 = json!({ "entry": cids[1].to_string(), "blocks": [cids[1].to_string()] });
        let (s, v2) = post(&ex, "/api/deal-index", req2.to_string().as_bytes());
        assert_eq!(s, 200, "{v2}");
        let unpaid: Cid = v2["root"].as_str().unwrap().parse().unwrap();
        // Blocks must be uploaded first, and the entry must be listed.
        let missing = json!({ "entry": cids[1].to_string(), "blocks": [sha256_cid(RAW, b"never").to_string()] });
        assert_eq!(post(&ex, "/api/deal-index", missing.to_string().as_bytes()).0, 400);

        // Quotes need open offers; unknown and malformed codes.
        assert_eq!(get(&ex, "/api/storage/quote?size=1000").0, 503);
        assert_eq!(get(&ex, "/api/storage/quote?size=0").0, 400);
        assert_eq!(get(&ex, "/api/cert/0000-0000-0000-0001").0, 404);
        assert_eq!(get(&ex, "/api/cert/abc").0, 400);
        let (_, st) = get(&ex, "/api/status");
        assert_eq!(st["certificates"]["contract"], json!(CERTS));

        // A block this node already had is never collected.
        let pre = b"already here".to_vec();
        let pre_cid = sha256_cid(RAW, &pre);
        {
            let w = ex.chain.store().writer().unwrap();
            w.put_ipld(&pre_cid, &pre).unwrap();
            w.commit().unwrap();
        }
        assert_eq!(post(&ex, "/api/upload", &body(&[&pre])).0, 200);

        // Fresh uploads survive a pass; after the deadlines the unpaid deal is deleted, the paid
        // one is kept.
        assert_eq!(collect(&ex).unwrap(), 0);
        let has = |c: &Cid| ex.chain.store().reader().unwrap().ipld(c).unwrap().is_some();
        assert!(has(&cids[1]));
        age(&ex, PAY_WITHIN.as_secs() + LOOSE_FOR.as_secs() + 1);
        assert!(collect(&ex).unwrap() >= 2, "b and the unpaid index");
        assert!(!has(&cids[1]) && !has(&unpaid), "unpaid deal deleted");
        assert!(has(&cids[0]) && has(&cids[2]) && has(&paid_root), "paid deal kept");
        assert!(has(&pre_cid), "pre-existing block kept");

        // The bookkeeping is saved and reloaded.
        let st: Uploads =
            serde_json::from_slice(&std::fs::read(d.path().join("uploads.json")).unwrap()).unwrap();
        assert!(st.blocks.is_empty() && st.roots.is_empty(), "{st:?}");
    }

    #[test]
    fn codes_roundtrip_and_forgive_typing() {
        for seed in 0u8..50 {
            let raw: [u8; 10] =
                std::array::from_fn(|i| seed.wrapping_mul(37).wrapping_add(i as u8 * 11));
            let s = encode_code(&raw);
            assert_eq!(s.len(), 16);
            assert_eq!(decode_code(&s), Some(raw));
            let messy = format!("{}-{} {}", &s[..4].to_lowercase(), &s[4..8], &s[8..]);
            assert_eq!(decode_code(&messy), Some(raw));
        }
        // Same vector as verify.js.
        let v = [0x00, 0x19, 0x32, 0x4b, 0x64, 0x7d, 0x96, 0xaf, 0xc8, 0xe1];
        assert_eq!(encode_code(&v), "00CK4JV4FPBAZJ71");
        assert_eq!(decode_code("0000000000000000"), Some([0; 10]));
        assert_eq!(decode_code("OOOO-IIII-LLLL-0000"), decode_code("0000-1111-1111-0000"));
        assert_eq!(decode_code("ZZZZZZZZZZZZZZZZ"), Some([0xff; 10]));
        assert!(decode_code("0000").is_none());
        assert!(decode_code("UUUUUUUUUUUUUUUU").is_none(), "U is not Crockford");
    }
}
