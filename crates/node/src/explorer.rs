//! Built-in block explorer (ADR 0010): a read-only JSON API over the node's database and a
//! single-page web interface (Traditional Chinese and English), both served on the gateway port
//! when the node runs with `--explorer`.
//!
//! API (all `GET`, JSON):
//! `/api/status`, `/api/blocks?before=&limit=`, `/api/txs?limit=`, `/api/block/<number|hash>`,
//! `/api/tx/<hash>`, `/api/address/<addr>?before=<block>-<index>&limit=`, `/api/validators`,
//! `/api/validator/<id>`, `/api/epoch/<n>`, `/api/search?q=`.

use crate::gateway::{Response, text};
use alloy_consensus::{Header, ReceiptEnvelope, Transaction as _, TxEnvelope};
use alloy_primitives::{Address, B256, Bytes, U256, hex};
use alloy_sol_types::SolCall;
use bolt_chain::Chain;
use bolt_ipld::{Cid, Envelope};
use bolt_store::{RO, StateView, Tx, addr_index::role};
use bolt_system::{abi::*, addresses::*, queries};
use bolt_txpool::TxPool;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

/// The web interface (one self-contained file).
const INDEX_HTML: &str = include_str!("explorer/index.html");
/// Evidence verification library (issue #1), used by the page and as its hashing Worker.
const VERIFY_JS: &str = include_str!("explorer/verify.js");
/// bolt-vault for the browser (`scripts/build-vault-wasm.sh`): compute jobs are sealed and
/// opened in the page.
const VAULT_JS: &str = include_str!("explorer/vault/bolt_vault.js");
const VAULT_WASM: &[u8] = include_bytes!("explorer/vault/bolt_vault_bg.wasm");

/// The page, with the library's URL versioned by its content (`/verify.js?v=<hash>`), so a
/// cached old library is never used with a new page.
fn index_html() -> &'static str {
    static PAGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| {
        let v = alloy_primitives::keccak256(VERIFY_JS.as_bytes());
        INDEX_HTML.replace("__VERIFY_VERSION__", &hex::encode(&v[..8]))
    })
}

/// Largest page size.
const MAX_LIMIT: usize = 50;

/// Everything the explorer reads.
#[derive(Debug, Clone)]
pub struct Explorer {
    /// Chain.
    pub chain: Arc<Chain>,
    /// Pool (pending transactions), if the node has one.
    pub pool: Option<Arc<TxPool>>,
    /// Evidence certificates (ADR 0016), when a `Certificates` contract is configured.
    pub certs: Option<Arc<crate::certificates::Certs>>,
    /// Block hosting (the node's storage service), for compute jobs posted from the browser.
    pub host: Option<Arc<dyn bolt_rpc::BlockHost>>,
}

pub(crate) type ApiResult = Result<Value, (u16, String)>;

fn json_response(res: ApiResult) -> Response {
    match res {
        Ok(v) => (200, "application/json", serde_json::to_vec(&v).unwrap_or_default()),
        Err((status, msg)) => (
            status,
            "application/json",
            serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default(),
        ),
    }
}

pub(crate) fn not_found(what: impl Into<String>) -> (u16, String) {
    (404, what.into())
}

pub(crate) fn internal(e: impl std::fmt::Display) -> (u16, String) {
    (500, e.to_string())
}

fn wei(v: U256) -> String {
    v.to_string()
}

/// Names of well-known contracts deployed on this network (`--explorer-labels`).
static LABELS: std::sync::OnceLock<HashMap<Address, String>> = std::sync::OnceLock::new();

/// Loads contract names from a JSON file: either `{ "<address>": "<name>" }` or a deployment
/// record `{ "contracts": { "<name>": "<address>" } }` (as written by
/// `scripts/uniswap-v4/deploy.mjs`). Several files can be given; later names win.
pub fn load_labels(paths: &[std::path::PathBuf]) -> anyhow::Result<usize> {
    let mut map = HashMap::new();
    for p in paths {
        let v: Value = serde_json::from_slice(&std::fs::read(p)?)
            .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
        let pairs: Vec<(String, String)> = match v.get("contracts").and_then(Value::as_object) {
            Some(c) => {
                c.iter().filter_map(|(n, a)| Some((a.as_str()?.to_owned(), n.clone()))).collect()
            }
            None => v
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(|(a, n)| Some((a.clone(), n.as_str()?.to_owned())))
                .collect(),
        };
        for (a, n) in pairs {
            let a: Address =
                a.parse().map_err(|_| anyhow::anyhow!("{}: bad address {a}", p.display()))?;
            map.insert(a, n);
        }
    }
    let n = map.len();
    let _ = LABELS.set(map);
    Ok(n)
}

/// Human name of a system contract or a labelled contract.
fn label(a: &Address) -> Option<String> {
    let system = match *a {
        STAKING => "StakingManager",
        CONSENSUS => "ConsensusRegistry",
        REWARDS => "RewardDistributor",
        SWARM => "SwarmStorage",
        COMPUTE => "ComputeMarket",
        SYSTEM => "System",
        _ => return LABELS.get().and_then(|m| m.get(a).cloned()),
    };
    Some(system.to_owned())
}

/// Method names for well-known selectors that are not decoded further (Uniswap v4, Permit2,
/// WETH-style wrappers, mintable tokens).
fn known_method(sel: [u8; 4]) -> Option<&'static str> {
    static TABLE: std::sync::OnceLock<HashMap<[u8; 4], &'static str>> = std::sync::OnceLock::new();
    const SIGS: &[(&str, &str)] = &[
        ("execute(bytes,bytes[],uint256)", "execute"),
        ("execute(bytes,bytes[])", "execute"),
        ("modifyLiquidities(bytes,uint256)", "modifyLiquidities"),
        ("modifyLiquiditiesWithoutUnlock(bytes,bytes[])", "modifyLiquiditiesWithoutUnlock"),
        ("initialize((address,address,uint24,int24,address),uint160)", "initialize"),
        ("initializePool((address,address,uint24,int24,address),uint160)", "initializePool"),
        ("multicall(bytes[])", "multicall"),
        ("approve(address,address,uint160,uint48)", "approve (Permit2)"),
        ("lockdown((address,address)[])", "lockdown"),
        ("invalidateNonces(address,address,uint48)", "invalidateNonces"),
        ("deposit()", "deposit"),
        ("withdraw(uint256)", "withdraw"),
        ("mint(address,uint256)", "mint"),
        ("setApprovalForAll(address,bool)", "setApprovalForAll"),
        ("safeTransferFrom(address,address,uint256)", "safeTransferFrom"),
    ];
    TABLE
        .get_or_init(|| {
            SIGS.iter()
                .map(|(sig, name)| {
                    let h = alloy_primitives::keccak256(sig.as_bytes());
                    ([h[0], h[1], h[2], h[3]], *name)
                })
                .collect()
        })
        .get(&sel)
        .copied()
}

pub(crate) fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
}

fn limit(query: &str, default: usize) -> usize {
    query_param(query, "limit").and_then(|v| v.parse().ok()).unwrap_or(default).clamp(1, MAX_LIMIT)
}

impl Explorer {
    /// Answers a request head. `/api/...` is JSON; everything else serves the web interface.
    pub fn respond(&self, req: &str, body: &[u8]) -> Option<Response> {
        let method = req.split_whitespace().next().unwrap_or("GET");
        let target = req.split_whitespace().nth(1).unwrap_or("/");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if path == "/" || path == "/index.html" || path == "/explorer" || is_page(path) {
            return Some((200, "text/html; charset=utf-8", index_html().as_bytes().to_vec()));
        }
        if path == "/verify.js" {
            return Some((200, "text/javascript; charset=utf-8", VERIFY_JS.as_bytes().to_vec()));
        }
        if path == "/vault/bolt_vault.js" {
            return Some((200, "text/javascript; charset=utf-8", VAULT_JS.as_bytes().to_vec()));
        }
        if path == "/vault/bolt_vault_bg.wasm" {
            return Some((200, "application/wasm", VAULT_WASM.to_vec()));
        }
        let api = path.strip_prefix("/api/")?;
        if method == "POST" {
            let res = match api {
                "upload" => self.upload(body),
                "deal-index" => self.deal_index(body),
                "compute/host" => self.compute_host(body),
                _ => Err((405, "only GET is supported here".to_string())),
            };
            return Some(json_response(res));
        }
        let r = match self.chain.store().reader() {
            Ok(r) => r,
            Err(e) => return Some(text(500, e.to_string())),
        };
        let parts: Vec<&str> = api.split('/').collect();
        let res = match parts.as_slice() {
            ["status"] => self.status(&r),
            ["blocks"] => self.blocks(&r, query),
            ["txs"] => self.latest_txs(&r, query),
            ["block", id] => self.block(&r, id),
            ["tx", h] => self.tx(&r, h),
            ["address", a] => self.address(&r, a, query),
            ["validators"] => self.validators(&r),
            ["validator", id] => self.validator(&r, id),
            ["epoch", n] => self.epoch(&r, n),
            ["search"] => self.search(&r, query_param(query, "q").unwrap_or("")),
            ["raw", "block", id] => self.raw_block(&r, id),
            ["proof", a] => self.proof(&r, a, query),
            ["call"] => self.call(&r, query),
            ["cert", code] => self.certificate(&r, code),
            ["storage", "quote"] => self.quote(&r, query),
            ["compute"] => self.compute(&r, query),
            ["compute", "job", id] => self.compute_job(&r, id),
            ["compute", "blocks"] => self.compute_blocks(query),
            ["tee"] => self.tee(&r, query),
            ["tee", "lease", id] => self.tee_lease(&r, id),
            ["tee", "machine", id] => self.tee_machine(&r, id),
            _ => Err(not_found("unknown API path")),
        };
        Some(json_response(res))
    }

    fn view<C: SolCall>(
        &self,
        r: &Tx<'_, RO>,
        to: Address,
        c: C,
    ) -> Result<C::Return, (u16, String)> {
        queries::call(&StateView::latest(r), self.chain.config().chain_id, to, c).map_err(internal)
    }

    pub(crate) fn head_header(&self, r: &Tx<'_, RO>) -> Result<Header, (u16, String)> {
        self.head(r)
    }

    fn head(&self, r: &Tx<'_, RO>) -> Result<Header, (u16, String)> {
        let n = r.head().map_err(internal)?.unwrap_or(0);
        r.header(n).map_err(internal)?.ok_or_else(|| internal("head missing"))
    }

    fn is_final(&self, number: u64) -> bool {
        self.chain.is_final(number).unwrap_or(false)
    }

    fn block_summary(&self, r: &Tx<'_, RO>, h: &Header) -> Value {
        let txs =
            r.block(h.number).ok().flatten().map(|b| b.transactions.len() as i64).unwrap_or(-1);
        json!({
            "number": h.number,
            "hash": h.hash_slow(),
            "timestamp": h.timestamp,
            "txs": txs,
            "gasUsed": h.gas_used,
            "gasLimit": h.gas_limit,
            "miner": h.beneficiary,
            "mined": !h.difficulty.is_zero(),
            "difficulty": wei(h.difficulty),
            "extra": extra_text(&h.extra_data),
        })
    }

    fn status(&self, r: &Tx<'_, RO>) -> ApiResult {
        let head = self.head(r)?;
        let rules = *self.chain.rules();
        let cfg = self.chain.config();
        let phase = self.chain.phase().map_err(internal)?;
        let next = head.number + 1;
        let stage = if phase.is_pos(&rules, next) {
            "pos"
        } else if phase.is_checkpointing(&rules, next) {
            "checkpoints"
        } else {
            "mining"
        };
        let (cp_stakers, cp_stake) = cfg.checkpoint_thresholds();
        let (pos_stakers, pos_stake, streak) = cfg.pos_thresholds();
        let stats = self.view(r, STAKING, IStakingManager::stakerStatsCall {})?;
        let supply = self.view(r, REWARDS, IRewardDistributor::supplyCall {})?;
        let validators = self.view(r, STAKING, IStakingManager::countCall {})?;
        // Hashrate from the work of the last 60 blocks and the time they took.
        let mut hashrate = 0f64;
        let mut block_time = 0f64;
        if head.number > 1 {
            let from = head.number.saturating_sub(60).max(1);
            if let Ok(Some(first)) = r.header(from) {
                let span = head.timestamp.saturating_sub(first.timestamp).max(1) as f64;
                let blocks = (head.number - from) as f64;
                block_time = span / blocks.max(1.0);
                let mut work = 0f64;
                for n in from + 1..=head.number {
                    if let Ok(Some(h)) = r.header(n) {
                        work += f64::from(h.difficulty);
                    }
                }
                hashrate = work / span;
            }
        }
        let finalized = self.chain.final_height().map_err(internal)?;
        let epoch = rules.epoch_of(next);
        Ok(json!({
            "chainId": cfg.chain_id,
            "version": crate::CLIENT_VERSION,
            "certificates": self.certs.as_ref().map(|c| json!({ "contract": c.address, "wallet": c.wallet })),
            "genesis": self.chain.genesis_hash(),
            "head": self.block_summary(r, &head),
            "finalized": finalized,
            "stage": stage,
            "epoch": epoch,
            "epochSlots": rules.epoch_slots,
            "epochFirst": epoch * rules.epoch_slots + 1,
            "blockTime": block_time,
            "targetBlockTime": if stage == "pos" { cfg.slot_seconds } else { cfg.pow.block_seconds },
            "hashrate": hashrate,
            "difficulty": wei(head.difficulty),
            "baseFee": head.base_fee_per_gas.unwrap_or_default(),
            "supply": wei(supply),
            "validators": validators,
            "stakers": wei(stats.stakers),
            "totalStake": wei(stats.total),
            "peers": bolt_primitives::metrics::PEERS.get(),
            "pending": self.pool.as_ref().map(|p| p.len()).unwrap_or(0),
            "phase": {
                "checkpointEpoch": phase.checkpoint_epoch,
                "posEpoch": phase.pos_epoch,
                "checkpointStreak": phase.checkpoint_streak,
                "posStreak": phase.streak,
                "streakRequired": streak,
                "checkpoint": { "stakers": cp_stakers, "stakeBolt": cp_stake },
                "pos": { "stakers": pos_stakers, "stakeBolt": pos_stake },
            },
            "addressIndexFrom": r.address_index_from().map_err(internal)?,
            "historyBase": r.base().map_err(internal)?,
        }))
    }

    fn blocks(&self, r: &Tx<'_, RO>, query: &str) -> ApiResult {
        let head = r.head().map_err(internal)?.unwrap_or(0);
        let before =
            query_param(query, "before").and_then(|v| v.parse::<u64>().ok()).unwrap_or(head + 1);
        let n = limit(query, 20) as u64;
        let mut out = Vec::new();
        let mut b = before.min(head + 1);
        while b > 0 && (out.len() as u64) < n {
            b -= 1;
            if let Some(h) = r.header(b).map_err(internal)? {
                out.push(self.block_summary(r, &h));
            }
        }
        Ok(json!({ "blocks": out, "head": head }))
    }

    fn latest_txs(&self, r: &Tx<'_, RO>, query: &str) -> ApiResult {
        let want = limit(query, 10);
        let head = r.head().map_err(internal)?.unwrap_or(0);
        let mut out = Vec::new();
        let mut n = head;
        let stop = head.saturating_sub(2000);
        while out.len() < want && n > stop {
            if let Some(b) = r.block(n).map_err(internal)? {
                for (i, tx) in b.transactions.iter().enumerate().rev() {
                    out.push(tx_summary(tx, b.senders.get(i).copied(), n, b.header.timestamp));
                    if out.len() >= want {
                        break;
                    }
                }
            }
            n -= 1;
        }
        Ok(json!({ "txs": out }))
    }

    /// A block as raw consensus bytes, for verifying in the browser without trusting this node:
    /// the header RLP (its keccak is the block hash), and every transaction and receipt in
    /// EIP-2718 encoding (their tries give `transactionsRoot` and `receiptsRoot`).
    fn raw_block(&self, r: &Tx<'_, RO>, id: &str) -> ApiResult {
        use alloy_eips::eip2718::Encodable2718;
        let n = self.resolve_block(r, id)?;
        let h = r.header(n).map_err(internal)?.ok_or_else(|| not_found("block not found"))?;
        let body = r.block(n).map_err(internal)?.ok_or_else(|| not_found("block body pruned"))?;
        let receipts =
            r.receipts(n).map_err(internal)?.ok_or_else(|| not_found("receipts pruned"))?;
        let txs: Vec<Bytes> = body.transactions.iter().map(|t| t.encoded_2718().into()).collect();
        let rcs: Vec<Bytes> = receipts.iter().map(|x| x.encoded_2718().into()).collect();
        Ok(json!({
            "number": n,
            "hash": h.hash_slow(),
            "final": self.is_final(n),
            "header": Bytes::from(alloy_rlp::encode(&h)),
            "transactions": txs,
            "receipts": rcs,
        }))
    }

    /// Latest head as raw header bytes (for state proofs and calls made against it).
    fn head_raw(&self, r: &Tx<'_, RO>) -> Result<(Header, Value), (u16, String)> {
        let h = self.head(r)?;
        let v = json!({
            "number": h.number,
            "hash": h.hash_slow(),
            "final": self.is_final(h.number),
            "timestamp": h.timestamp,
            "header": Bytes::from(alloy_rlp::encode(&h)),
        });
        Ok((h, v))
    }

    /// EIP-1186 proof of an account and storage slots (`?slots=0x..,0x..`) in the latest state,
    /// with the head header they verify against. Only the latest state has proofs.
    fn proof(&self, r: &Tx<'_, RO>, a: &str, query: &str) -> ApiResult {
        let addr: Address = a.parse().map_err(|_| (400, "bad address".to_string()))?;
        let mut keys = Vec::new();
        for s in query_param(query, "slots").unwrap_or("").split(',').filter(|s| !s.is_empty()) {
            let k: B256 = s.parse().map_err(|_| (400, format!("bad slot {s}")))?;
            keys.push(k.into());
        }
        if keys.len() > 16 {
            return Err((400, "at most 16 slots".into()));
        }
        let (_, block) = self.head_raw(r)?;
        let proof = bolt_rpc::get_proof(r, addr, keys).map_err(internal)?;
        Ok(json!({ "block": block, "proof": proof }))
    }

    /// Read-only call (`?to=0x..&data=0x..`) against the latest state; returns the output and the
    /// block it ran on. The output is only as trustworthy as this node.
    fn call(&self, r: &Tx<'_, RO>, query: &str) -> ApiResult {
        let to: Address = query_param(query, "to")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| (400, "to: expected an address".to_string()))?;
        let data: Bytes = query_param(query, "data")
            .unwrap_or("0x")
            .parse()
            .map_err(|_| (400, "data: expected hex".to_string()))?;
        let (h, block) = self.head_raw(r)?;
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
        let db = revm::database::WrapDatabaseRef(StateView::latest(r));
        match bolt_exec::view_call(db, &input, to, data) {
            Ok(out) => Ok(json!({ "block": block, "output": out })),
            Err(bolt_exec::ViewError::Reverted) => Err((400, "execution reverted".into())),
            Err(e) => Err(internal(format!("{e:?}"))),
        }
    }

    fn resolve_block(&self, r: &Tx<'_, RO>, id: &str) -> Result<u64, (u16, String)> {
        if let Ok(n) = id.parse::<u64>() {
            return Ok(n);
        }
        let h: B256 =
            id.parse().map_err(|_| (400, "expected a block number or hash".to_string()))?;
        r.block_number(&h).map_err(internal)?.ok_or_else(|| not_found("block not found"))
    }

    fn block(&self, r: &Tx<'_, RO>, id: &str) -> ApiResult {
        let n = self.resolve_block(r, id)?;
        let h = r.header(n).map_err(internal)?.ok_or_else(|| not_found("block not found"))?;
        let body = r.block(n).map_err(internal)?;
        let receipts = r.receipts(n).map_err(internal)?.unwrap_or_default();
        let root = r.envelope_root(n).map_err(internal)?;
        let env =
            root.and_then(|c| r.ipld(&c).ok().flatten()).and_then(|b| Envelope::decode(&b).ok());
        let txs: Vec<Value> = match &body {
            Some(b) => b
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    let mut s = tx_summary(tx, b.senders.get(i).copied(), n, h.timestamp);
                    if let Some(rc) = receipts.get(i) {
                        s["success"] = json!(rc.status());
                    }
                    s
                })
                .collect(),
            None => vec![],
        };
        let rules = self.chain.rules();
        let burned = U256::from(h.base_fee_per_gas.unwrap_or_default()) * U256::from(h.gas_used);
        Ok(json!({
            "number": n,
            "hash": h.hash_slow(),
            "parentHash": h.parent_hash,
            "timestamp": h.timestamp,
            "miner": h.beneficiary,
            "minerLabel": label(&h.beneficiary),
            "mined": !h.difficulty.is_zero(),
            "difficulty": wei(h.difficulty),
            "nonce": h.nonce,
            "gasUsed": h.gas_used,
            "gasLimit": h.gas_limit,
            "baseFee": h.base_fee_per_gas.unwrap_or_default(),
            "burned": wei(burned),
            "stateRoot": h.state_root,
            "transactionsRoot": h.transactions_root,
            "receiptsRoot": h.receipts_root,
            "extra": extra_text(&h.extra_data),
            "extraHex": h.extra_data,
            "size": alloy_rlp::Encodable::length(&h),
            "epoch": rules.epoch_of(n),
            "final": self.is_final(n),
            "bodyAvailable": body.is_some(),
            "txs": txs,
            "ipfs": env.as_ref().map(|e| json!({
                "root": root.map(|c| c.to_string()),
                "header": e.header.to_string(),
                "parent": e.parent.map(|c| c.to_string()),
                "chunks": e.chunks.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "certificate": !e.qc.is_empty(),
                "audits": e.audits.len(),
            })),
        }))
    }

    fn tx(&self, r: &Tx<'_, RO>, hash: &str) -> ApiResult {
        let h: B256 = hash.parse().map_err(|_| (400, "expected a transaction hash".to_string()))?;
        let Some((n, i)) = r.tx_location(&h).map_err(internal)? else {
            if let Some(p) = self.pool.as_ref().and_then(|p| p.get(&h)) {
                let mut v = tx_detail(&p.tx, p.sender, None);
                v["pending"] = json!(true);
                return Ok(v);
            }
            return Err(not_found("transaction not found"));
        };
        let b = r.block(n).map_err(internal)?.ok_or_else(|| not_found("block body pruned"))?;
        let i = i as usize;
        let tx = b.transactions.get(i).ok_or_else(|| internal("index out of range"))?;
        let receipts = r.receipts(n).map_err(internal)?.unwrap_or_default();
        let sender = b.senders.get(i).copied().unwrap_or_default();
        let mut v = tx_detail(tx, sender, receipts.get(i));
        let gas_used = receipts.get(i).map(|rc| {
            let prev = if i == 0 { 0 } else { receipts[i - 1].cumulative_gas_used() };
            rc.cumulative_gas_used() - prev
        });
        let base = b.header.base_fee_per_gas.unwrap_or_default() as u128;
        let price = tx.effective_gas_price(Some(base as u64));
        v["block"] = json!(n);
        v["blockHash"] = json!(b.header.hash_slow());
        v["index"] = json!(i);
        v["timestamp"] = json!(b.header.timestamp);
        v["final"] = json!(self.is_final(n));
        v["pending"] = json!(false);
        if let Some(g) = gas_used {
            v["gasUsed"] = json!(g);
            v["gasPrice"] = json!(price.to_string());
            v["fee"] = json!((U256::from(g) * U256::from(price)).to_string());
            v["burned"] = json!((U256::from(g) * U256::from(base)).to_string());
        }
        if tx.kind().is_create() {
            v["created"] = json!(sender.create(tx.nonce()));
        }
        Ok(v)
    }

    fn address(&self, r: &Tx<'_, RO>, a: &str, query: &str) -> ApiResult {
        let addr: Address = a.parse().map_err(|_| (400, "expected an address".to_string()))?;
        let acc = r.account(&addr).map_err(internal)?;
        let code_len = match &acc {
            Some(a) if a.code_hash != alloy_primitives::KECCAK256_EMPTY => {
                r.code(&a.code_hash).map_err(internal)?.map(|c| c.len()).unwrap_or(0)
            }
            _ => 0,
        };
        let before = query_param(query, "before").and_then(|v| {
            let (b, i) = v.split_once('-')?;
            Some((b.parse().ok()?, i.parse().ok()?))
        });
        let n = limit(query, 25);
        let index_from = r.address_index_from().map_err(internal)?;
        let entries = if index_from.is_some() {
            r.address_txs(&addr, before, n + 1).map_err(internal)?
        } else {
            vec![]
        };
        let more = entries.len() > n;
        let mut txs = Vec::new();
        for e in entries.iter().take(n) {
            let Some(b) = r.block(e.block).map_err(internal)? else { continue };
            let Some(tx) = b.transactions.get(e.index as usize) else { continue };
            let mut s = tx_summary(
                tx,
                b.senders.get(e.index as usize).copied(),
                e.block,
                b.header.timestamp,
            );
            s["roles"] = json!(roles(e.roles));
            if let Some(rc) = r
                .receipts(e.block)
                .map_err(internal)?
                .and_then(|v| v.get(e.index as usize).cloned())
            {
                s["success"] = json!(rc.status());
                // Token transfers this address took part in.
                let transfers: Vec<Value> = rc
                    .logs()
                    .iter()
                    .filter_map(transfer_of)
                    .filter(|t| t["from"] == json!(addr) || t["to"] == json!(addr))
                    .collect();
                if !transfers.is_empty() {
                    s["transfers"] = json!(transfers);
                }
            }
            txs.push(s);
        }
        // Validators this address owns (scan; the testnet has few).
        let count = self.view(r, STAKING, IStakingManager::countCall {})?;
        let mut owned = Vec::new();
        for id in 1..=count.min(2000) {
            let v = self.view(r, STAKING, IStakingManager::validatorCall { id })?;
            if v.owner == addr || v.feeRecipient == addr {
                owned.push(json!({ "id": id, "owner": v.owner == addr, "stake": wei(v.stake), "status": status_name(v.status as u8) }));
            }
        }
        let next = if more {
            entries.get(n - 1).map(|e| format!("{}-{}", e.block, e.index))
        } else {
            None
        };
        Ok(json!({
            "address": addr,
            "label": label(&addr),
            "balance": wei(acc.as_ref().map(|a| a.balance).unwrap_or_default()),
            "nonce": acc.as_ref().map(|a| a.nonce).unwrap_or_default(),
            "contract": code_len > 0,
            "codeSize": code_len,
            "validators": owned,
            "txs": txs,
            "next": next,
            "indexFrom": index_from,
        }))
    }

    fn validators(&self, r: &Tx<'_, RO>) -> ApiResult {
        let count = self.view(r, STAKING, IStakingManager::countCall {})?;
        let head = r.head().map_err(internal)?.unwrap_or(0);
        let epoch = self.chain.rules().epoch_of(head + 1);
        let committee = self.view(r, CONSENSUS, IConsensusRegistry::committeeCall { epoch })?;
        let mut list = Vec::new();
        for id in 1..=count.min(2000) {
            let v = self.view(r, STAKING, IStakingManager::validatorCall { id })?;
            let rewards = self.view(r, REWARDS, IRewardDistributor::rewardsCall { id })?;
            let seats = committee
                .ids
                .iter()
                .zip(&committee.weights)
                .find(|(i, _)| **i == id)
                .map(|(_, w)| *w)
                .unwrap_or(0);
            let peer = self.view(r, SWARM, ISwarmStorage::peerOfCall { id })?;
            list.push(json!({
                "id": id,
                "owner": v.owner,
                "feeRecipient": v.feeRecipient,
                "stake": wei(v.stake),
                "status": status_name(v.status as u8),
                "rewards": wei(rewards),
                "seats": seats,
                "historyPeer": !peer.is_empty(),
            }));
        }
        Ok(
            json!({ "epoch": epoch, "validators": list, "committeeSeats": committee.weights.iter().map(|w| *w as u64).sum::<u64>() }),
        )
    }

    fn validator(&self, r: &Tx<'_, RO>, id: &str) -> ApiResult {
        let id: u32 = id.parse().map_err(|_| (400, "expected a validator id".to_string()))?;
        let count = self.view(r, STAKING, IStakingManager::countCall {})?;
        if id == 0 || id > count {
            return Err(not_found("validator not found"));
        }
        let v = self.view(r, STAKING, IStakingManager::validatorCall { id })?;
        let rewards = self.view(r, REWARDS, IRewardDistributor::rewardsCall { id })?;
        let peer = self.view(r, SWARM, ISwarmStorage::peerOfCall { id })?;
        let head = r.head().map_err(internal)?.unwrap_or(0);
        let rules = self.chain.rules();
        let cur = rules.epoch_of(head + 1);
        let mut committees = Vec::new();
        let mut audits = Vec::new();
        for e in cur.saturating_sub(9)..=cur + 1 {
            let c = self.view(r, CONSENSUS, IConsensusRegistry::committeeCall { epoch: e })?;
            if let Some(pos) = c.ids.iter().position(|i| *i == id) {
                committees.push(json!({ "epoch": e, "seats": c.weights[pos] }));
            }
            if e > cur {
                continue;
            }
            let a = self.view(r, SWARM, ISwarmStorage::auditsCall { epoch: e })?;
            let kinds =
                self.view(r, SWARM, ISwarmStorage::taskKindsCall { epoch: e }).unwrap_or_default();
            for (task, p) in a.providers.iter().enumerate() {
                if *p == id {
                    audits.push(json!({
                        "epoch": e, "task": task, "target": a.targets[task], "height": a.heights[task],
                        "state": audit_state(a.states[task]), "kind": task_kind(&kinds, task),
                    }));
                }
            }
        }
        Ok(json!({
            "id": id,
            "owner": v.owner,
            "feeRecipient": v.feeRecipient,
            "stake": wei(v.stake),
            "status": status_name(v.status as u8),
            "exitEpoch": v.exitEpoch,
            "pubkey": v.pubkey,
            "rewards": wei(rewards),
            "historyPeer": libp2p::PeerId::from_bytes(&peer).ok().map(|p| p.to_string()),
            "committees": committees,
            "audits": audits,
        }))
    }

    fn epoch(&self, r: &Tx<'_, RO>, n: &str) -> ApiResult {
        let e: u64 = n.parse().map_err(|_| (400, "expected an epoch number".to_string()))?;
        let rules = self.chain.rules();
        let first = e * rules.epoch_slots + 1;
        let last = rules.epoch_end(e);
        let head = r.head().map_err(internal)?.unwrap_or(0);
        let c = self.view(r, CONSENSUS, IConsensusRegistry::committeeCall { epoch: e })?;
        let idx = self.view(r, SWARM, ISwarmStorage::epochIndexCall { epoch: e })?;
        let a = self.view(r, SWARM, ISwarmStorage::auditsCall { epoch: e })?;
        let kinds =
            self.view(r, SWARM, ISwarmStorage::taskKindsCall { epoch: e }).unwrap_or_default();
        let tasks: Vec<Value> = (0..a.providers.len())
            .map(|i| json!({
                "task": i, "provider": a.providers[i], "target": a.targets[i], "height": a.heights[i],
                "state": audit_state(a.states[i]), "kind": task_kind(&kinds, i),
            }))
            .collect();
        let phase = self.chain.phase().map_err(internal)?;
        let mode = if phase.pos_epoch.is_some_and(|p| e >= p) {
            "pos"
        } else if phase.is_checkpoint_epoch(e) {
            "checkpoints"
        } else {
            "mining"
        };
        Ok(json!({
            "epoch": e,
            "first": first,
            "last": last,
            "complete": head >= last,
            "mode": mode,
            "committee": c.ids.iter().zip(&c.weights).map(|(i, w)| json!({ "id": i, "seats": w })).collect::<Vec<_>>(),
            "index": Cid::try_from(idx.as_ref()).ok().map(|c| c.to_string()),
            "auditPanel": a.panel,
            "audits": tasks,
        }))
    }

    fn search(&self, r: &Tx<'_, RO>, q: &str) -> ApiResult {
        let q = q.trim();
        let go = |kind: &str, id: String| Ok(json!({ "kind": kind, "id": id }));
        if q.is_empty() {
            return Err((400, "empty query".into()));
        }
        if let Ok(n) = q.parse::<u64>() {
            return go("block", n.to_string());
        }
        if let Some(rest) = q.strip_prefix("epoch:").or_else(|| q.strip_prefix("epoch ")) {
            return go("epoch", rest.trim().to_string());
        }
        if let Some(rest) = q.strip_prefix("v:").or_else(|| q.strip_prefix("validator ")) {
            return go("validator", rest.trim().to_string());
        }
        if q.len() == 42 && q.parse::<Address>().is_ok() {
            return go("address", q.to_string());
        }
        if let Ok(h) = q.parse::<B256>() {
            if r.block_number(&h).map_err(internal)?.is_some() {
                return go("block", format!("{h}"));
            }
            if r.tx_location(&h).map_err(internal)?.is_some()
                || self.pool.as_ref().is_some_and(|p| p.get(&h).is_some())
            {
                return go("tx", format!("{h}"));
            }
            return Err(not_found("no block or transaction with this hash"));
        }
        if let Ok(c) = Cid::try_from(q) {
            if let Some(h) = bolt_ipld::block_hash_of(&c) {
                return go("block", format!("{h}"));
            }
            return Ok(json!({ "kind": "cid", "id": c.to_string() }));
        }
        Err(not_found("nothing matches"))
    }
}

fn extra_text(extra: &Bytes) -> Option<String> {
    let s = std::str::from_utf8(extra).ok()?;
    (!s.is_empty() && s.chars().all(|c| !c.is_control())).then(|| s.to_string())
}

fn status_name(s: u8) -> &'static str {
    ["none", "active", "exiting", "slashed", "withdrawn"]
        .get(s as usize)
        .copied()
        .unwrap_or("unknown")
}

/// Audit task kind (ADR 0014): "history" (target = epoch, height = block) or "deal" (target =
/// deal id, height = block index in the deal).
fn task_kind(kinds: &[u8], task: usize) -> &'static str {
    if kinds.get(task) == Some(&1) { "deal" } else { "history" }
}

fn audit_state(s: u8) -> &'static str {
    ["pending", "passed", "failed"].get(s as usize).copied().unwrap_or("unknown")
}

fn roles(r: u8) -> Vec<&'static str> {
    [
        (role::FROM, "from"),
        (role::TO, "to"),
        (role::CREATED, "created"),
        (role::TOKEN, "token"),
        (role::TOKEN_CONTRACT, "tokenContract"),
    ]
    .into_iter()
    .filter(|(f, _)| r & f != 0)
    .map(|(_, n)| n)
    .collect()
}

fn tx_summary(tx: &TxEnvelope, sender: Option<Address>, block: u64, timestamp: u64) -> Value {
    let call = decode_call(tx.to(), tx.input());
    json!({
        "hash": tx.tx_hash(),
        "block": block,
        "timestamp": timestamp,
        "from": sender,
        "to": tx.to(),
        "toLabel": tx.to().as_ref().and_then(label),
        "value": tx.value().to_string(),
        "method": call.as_ref().map(|c| c["method"].clone()),
        "create": tx.kind().is_create(),
    })
}

fn tx_detail(tx: &TxEnvelope, sender: Address, receipt: Option<&ReceiptEnvelope>) -> Value {
    let logs: Vec<Value> = receipt
        .map(|r| {
            r.logs()
                .iter()
                .map(|l| {
                    json!({
                        "address": l.address,
                        "label": label(&l.address),
                        "topics": l.topics(),
                        "data": l.data.data,
                        "transfer": transfer_of(l),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "hash": tx.tx_hash(),
        "type": u8::from(tx.tx_type()),
        "from": sender,
        "to": tx.to(),
        "toLabel": tx.to().as_ref().and_then(label),
        "value": tx.value().to_string(),
        "nonce": tx.nonce(),
        "gasLimit": tx.gas_limit(),
        "maxFeePerGas": tx.max_fee_per_gas().to_string(),
        "maxPriorityFeePerGas": tx.max_priority_fee_per_gas().map(|v| v.to_string()),
        "input": tx.input(),
        "call": decode_call(tx.to(), tx.input()),
        "success": receipt.map(|r| r.status()),
        "logs": logs,
    })
}

/// A token `Transfer` log, decoded.
fn transfer_of(l: &alloy_primitives::Log) -> Option<Value> {
    let t = l.topics();
    if t.len() == 3 && t[0] == bolt_store::addr_index::TRANSFER_TOPIC {
        let amount = U256::from_be_slice(&l.data.data[..l.data.data.len().min(32)]);
        return Some(json!({
            "token": l.address,
            "tokenLabel": label(&l.address),
            "from": Address::from_word(t[1]),
            "fromLabel": label(&Address::from_word(t[1])),
            "to": Address::from_word(t[2]),
            "toLabel": label(&Address::from_word(t[2])),
            "amount": amount.to_string(),
        }));
    }
    if t.len() == 4 && t[0] == bolt_store::addr_index::TRANSFER_TOPIC {
        return Some(json!({
            "token": l.address,
            "tokenLabel": label(&l.address),
            "from": Address::from_word(t[1]),
            "fromLabel": label(&Address::from_word(t[1])),
            "to": Address::from_word(t[2]),
            "toLabel": label(&Address::from_word(t[2])),
            "tokenId": U256::from_be_bytes(t[3].0).to_string(),
        }));
    }
    None
}

/// Decodes calls to the system contracts and common token calls into a method name and named
/// parameters.
fn decode_call(to: Option<Address>, input: &Bytes) -> Option<Value> {
    if input.len() < 4 {
        return None;
    }
    let sel: [u8; 4] = input[..4].try_into().ok()?;
    let p = |pairs: Vec<(&str, Value)>| {
        pairs.into_iter().map(|(n, v)| json!({ "name": n, "value": v })).collect::<Vec<_>>()
    };
    let out =
        |method: &str, params: Vec<Value>| Some(json!({ "method": method, "params": params }));
    let to = to?;
    if to == STAKING {
        use IStakingManager::*;
        if sel == registerCall::SELECTOR {
            let c = registerCall::abi_decode(input).ok()?;
            return out(
                "register",
                p(vec![("pubkey", json!(c.pubkey)), ("feeRecipient", json!(c.feeRecipient))]),
            );
        }
        if sel == depositCall::SELECTOR {
            let c = depositCall::abi_decode(input).ok()?;
            return out("deposit", p(vec![("id", json!(c.id))]));
        }
        if sel == requestExitCall::SELECTOR {
            let c = requestExitCall::abi_decode(input).ok()?;
            return out("requestExit", p(vec![("id", json!(c.id))]));
        }
        if sel == withdrawCall::SELECTOR {
            let c = withdrawCall::abi_decode(input).ok()?;
            return out("withdraw", p(vec![("id", json!(c.id))]));
        }
        if sel == setFeeRecipientCall::SELECTOR {
            let c = setFeeRecipientCall::abi_decode(input).ok()?;
            return out(
                "setFeeRecipient",
                p(vec![("id", json!(c.id)), ("feeRecipient", json!(c.feeRecipient))]),
            );
        }
    }
    if to == SWARM && sel == ISwarmStorage::setPeerCall::SELECTOR {
        let c = ISwarmStorage::setPeerCall::abi_decode(input).ok()?;
        let peer = libp2p::PeerId::from_bytes(&c.peerId)
            .map(|p| p.to_string())
            .unwrap_or_else(|_| hex::encode_prefixed(&c.peerId));
        return out("setPeer", p(vec![("id", json!(c.id)), ("peerId", json!(peer))]));
    }
    if to == REWARDS && sel == IRewardDistributor::claimCall::SELECTOR {
        let c = IRewardDistributor::claimCall::abi_decode(input).ok()?;
        return out("claim", p(vec![("id", json!(c.id))]));
    }
    if to == CONSENSUS && sel == IConsensusRegistry::submitEvidenceCall::SELECTOR {
        let c = IConsensusRegistry::submitEvidenceCall::abi_decode(input).ok()?;
        return out("submitEvidence", p(vec![("id", json!(c.id))]));
    }
    // ERC-20: transfer, approve, transferFrom.
    let word = |i: usize| input.get(4 + 32 * i..4 + 32 * (i + 1));
    let addr = |i: usize| word(i).map(|w| Address::from_slice(&w[12..]));
    let amount = |i: usize| word(i).map(|w| U256::from_be_slice(w).to_string());
    match sel {
        [0xa9, 0x05, 0x9c, 0xbb] if input.len() == 68 => {
            out("transfer", p(vec![("to", json!(addr(0)?)), ("amount", json!(amount(1)?))]))
        }
        [0x09, 0x5e, 0xa7, 0xb3] if input.len() == 68 => {
            out("approve", p(vec![("spender", json!(addr(0)?)), ("amount", json!(amount(1)?))]))
        }
        [0x23, 0xb8, 0x72, 0xdd] if input.len() == 100 => out(
            "transferFrom",
            p(vec![
                ("from", json!(addr(0)?)),
                ("to", json!(addr(1)?)),
                ("amount", json!(amount(2)?)),
            ]),
        ),
        _ => Some(json!({
            "method": known_method(sel).map(str::to_owned).unwrap_or_else(|| hex::encode_prefixed(sel)),
            "params": []
        })),
    }
}

/// A page of the single-page interface (`/blocks`, `/block/12`, `/tx/0x…`, …): the browser asks
/// for it on a reload or a shared link, and the page's script routes on the path.
fn is_page(path: &str) -> bool {
    let mut parts = path.trim_start_matches('/').split('/');
    let (page, arg, rest) = (parts.next().unwrap_or(""), parts.next(), parts.next());
    rest.is_none()
        && match page {
            "blocks" | "validators" | "verify" | "compute" | "tee" => arg.is_none_or(str::is_empty),
            "job" | "lease" | "machine" => arg.is_some_and(|a| !a.is_empty()),
            "block" | "tx" | "address" | "validator" | "epoch" | "cert" => {
                arg.is_some_and(|a| !a.is_empty())
            }
            _ => false,
        }
}

/// Serves the explorer (and the IPFS gateway behind it) on `addr`.
pub async fn start(
    addr: std::net::SocketAddr,
    explorer: Explorer,
) -> anyhow::Result<std::net::SocketAddr> {
    let chain = explorer.chain.clone();
    let explorer = Arc::new(explorer);
    if explorer.certs.is_some() {
        crate::certificates::spawn_collector(explorer.clone());
    }
    let handler = move |req: &str, body: &[u8]| {
        explorer.respond(req, body).unwrap_or_else(|| crate::gateway::respond(&chain, req))
    };
    let bound = crate::gateway::serve(addr, Arc::new(handler)).await?;
    tracing::info!(%bound, "block explorer and IPFS gateway listening");
    Ok(bound)
}

/// Turns on the address index and fills it for older blocks in the background, newest first.
pub fn spawn_address_index(chain: Arc<Chain>) -> anyhow::Result<()> {
    {
        let w = chain.store().writer()?;
        let from = w.enable_address_index()?;
        w.commit()?;
        tracing::info!(from, "address index enabled; indexing older blocks in the background");
    }
    std::thread::spawn(move || {
        let mut total = 0u64;
        loop {
            let step = chain.store().writer().and_then(|w| {
                let n = w.index_blocks(200)?;
                w.commit()?;
                Ok(n)
            });
            match step {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) => {
                    tracing::warn!("address index: {e}");
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        tracing::info!(blocks = total, "address index complete");
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(ex: &Explorer, path: &str) -> (u16, Value) {
        let (status, _, body) =
            ex.respond(&format!("GET {path} HTTP/1.1\r\n\r\n"), &[]).expect("handled");
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    #[test]
    fn api_serves_chain_data() {
        let g =
            bolt_primitives::Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap();
        let d = tempfile::tempdir().unwrap();
        let chain = Arc::new(Chain::open(d.path(), &g).unwrap());
        {
            let w = chain.store().writer().unwrap();
            w.enable_address_index().unwrap();
            w.commit().unwrap();
        }
        let ex = Explorer { chain, pool: None, certs: None, host: None };
        let (s, v) = get(&ex, "/api/status");
        assert_eq!(s, 200);
        assert_eq!(v["chainId"], 1337);
        assert_eq!(v["stage"], "pos");
        assert_eq!(v["validators"], 7);
        let version = v["version"].as_str().unwrap();
        let commit = version.strip_prefix(concat!("boltchain/v", env!("CARGO_PKG_VERSION"), "-"));
        assert!(
            commit.is_some_and(|c| c == "unknown"
                || c.trim_end_matches("-dirty").len() == 7
                    && c.trim_end_matches("-dirty").bytes().all(|b| b.is_ascii_hexdigit())),
            "version names the commit: {version}"
        );
        let (_, v) = get(&ex, "/api/block/0");
        assert_eq!(v["number"], 0);
        assert!(v["ipfs"]["root"].is_string());
        let (_, v) = get(&ex, "/api/validators");
        assert_eq!(v["validators"].as_array().unwrap().len(), 7);
        assert_eq!(v["validators"][0]["status"], "active");
        let (_, v) = get(&ex, "/api/validator/3");
        assert_eq!(v["id"], 3);
        let (_, v) = get(&ex, "/api/epoch/0");
        assert!(!v["committee"].as_array().unwrap().is_empty());
        let (_, v) = get(&ex, "/api/address/0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_ne!(v["balance"], "0");
        assert_eq!(v["indexFrom"], 1);
        let (_, v) = get(&ex, "/api/search?q=0");
        assert_eq!(v["kind"], "block");
        let (_, v) = get(&ex, &format!("/api/search?q={}", STAKING));
        assert_eq!(v["kind"], "address");
        // Raw block: the header RLP hashes to the block hash; receipts give receiptsRoot.
        let (s, v) = get(&ex, "/api/raw/block/0");
        assert_eq!(s, 200);
        let hdr: Bytes = serde_json::from_value(v["header"].clone()).unwrap();
        assert_eq!(json!(alloy_primitives::keccak256(&hdr)), v["hash"]);
        // State proof of a system contract verifies against the head's stateRoot.
        let (s, v) = get(&ex, &format!("/api/proof/{STAKING}?slots=0x{}", "00".repeat(32)));
        assert_eq!(s, 200, "{v}");
        let hdr: Bytes = serde_json::from_value(v["block"]["header"].clone()).unwrap();
        let head = <Header as alloy_rlp::Decodable>::decode(&mut hdr.as_ref()).unwrap();
        let p: alloy_rpc_types_eth::EIP1186AccountProofResponse =
            serde_json::from_value(v["proof"].clone()).unwrap();
        let acct = alloy_trie::TrieAccount {
            nonce: p.nonce,
            balance: p.balance,
            storage_root: p.storage_hash,
            code_hash: p.code_hash,
        };
        alloy_trie::proof::verify_proof(
            head.state_root,
            alloy_trie::Nibbles::unpack(alloy_primitives::keccak256(STAKING)),
            Some(alloy_rlp::encode(acct)),
            &p.account_proof,
        )
        .unwrap();
        assert_eq!(get(&ex, "/api/proof/0x01?slots=zz").0, 400);
        // Read-only call: StakingManager.count() is the 7 genesis validators.
        let data = Bytes::from(IStakingManager::countCall {}.abi_encode());
        let (s, v) = get(&ex, &format!("/api/call?to={STAKING}&data={data}"));
        assert_eq!(s, 200, "{v}");
        let out: Bytes = serde_json::from_value(v["output"].clone()).unwrap();
        assert_eq!(U256::from_be_slice(&out), U256::from(7));
        assert_eq!(get(&ex, "/api/call?to=0x01").0, 400);
        assert_eq!(get(&ex, "/api/tx/0x00").0, 400);
        assert_eq!(get(&ex, "/api/nope").0, 404);
        let (s, ct, body) = ex.respond("GET / HTTP/1.1\r\n\r\n", &[]).unwrap();
        assert_eq!((s, ct), (200, "text/html; charset=utf-8"));
        assert!(String::from_utf8(body).unwrap().contains("Boltchain"));
        assert!(ex.respond("GET /ipfs/x HTTP/1.1\r\n\r\n", &[]).is_none(), "left to the gateway");
        let (s, ct, body) = ex.respond("GET /verify.js HTTP/1.1\r\n\r\n", &[]).unwrap();
        assert_eq!((s, ct), (200, "text/javascript; charset=utf-8"));
        assert!(String::from_utf8(body).unwrap().contains("verifyEvidence"));
        let (_, _, page) = ex.respond("GET /verify HTTP/1.1\r\n\r\n", &[]).unwrap();
        let page = String::from_utf8(page).unwrap();
        assert!(!page.contains("__VERIFY_VERSION__"));
        assert!(page.contains("/verify.js?v="), "the library URL is versioned");
        let (_, _, page) = ex.respond("GET /verify HTTP/1.1\r\n\r\n", &[]).unwrap();
        let page = String::from_utf8(page).unwrap();
        assert!(!page.contains("__VERIFY_VERSION__"));
        assert!(page.contains("/verify.js?v="), "the library URL is versioned");
        for page in [
            "/blocks",
            "/blocks?before=26",
            "/block/12",
            "/tx/0xab",
            "/address/0x01",
            "/validators",
            "/validator/3",
            "/epoch/4",
            "/verify",
            "/compute",
            "/job/3",
            "/tee",
            "/lease/1",
            "/machine/2",
        ] {
            let (s, ct, _) = ex.respond(&format!("GET {page} HTTP/1.1\r\n\r\n"), &[]).unwrap();
            assert_eq!((s, ct), (200, "text/html; charset=utf-8"), "{page}");
        }
        let (s, ct, wasm) =
            ex.respond("GET /vault/bolt_vault_bg.wasm HTTP/1.1\r\n\r\n", &[]).unwrap();
        assert_eq!((s, ct), (200, "application/wasm"));
        assert!(wasm.starts_with(b"\0asm"));
        let (_, v) = get(&ex, "/api/compute");
        assert_eq!(v["enabled"], true);
        assert_eq!(v["jobCount"], 0);
        let (_, v) = get(&ex, "/api/tee");
        assert_eq!(v["enabled"], true);
        assert_eq!(v["collateral"]["root"], "simulated");
        assert_eq!(get(&ex, "/api/tee/lease/1").0, 404);
        assert_eq!(get(&ex, "/api/compute/blocks?cids=x").0, 503, "no block host here");
        for other in ["/block", "/block/1/x", "/favicon.ico", "/blockz/1", "/job"] {
            assert!(ex.respond(&format!("GET {other} HTTP/1.1\r\n\r\n"), &[]).is_none(), "{other}");
        }
    }

    #[test]
    fn decodes_system_and_token_calls() {
        let data =
            ISwarmStorage::setPeerCall { id: 4, peerId: Bytes::from(vec![0, 1]) }.abi_encode();
        let c = decode_call(Some(SWARM), &data.into()).unwrap();
        assert_eq!(c["method"], "setPeer");
        let mut t = vec![0xa9, 0x05, 0x9c, 0xbb];
        t.extend([0u8; 12]);
        t.extend(Address::repeat_byte(7).as_slice());
        t.extend(U256::from(5).to_be_bytes::<32>());
        let c = decode_call(Some(Address::repeat_byte(1)), &t.into()).unwrap();
        assert_eq!(c["method"], "transfer");
        assert_eq!(c["params"][1]["value"], "5");
        // UniversalRouter.execute(bytes,bytes[],uint256): named, not decoded.
        let c =
            decode_call(Some(Address::repeat_byte(1)), &Bytes::from(vec![0x35, 0x93, 0x56, 0x4c]))
                .unwrap();
        assert_eq!(c["method"], "execute");
    }

    #[test]
    fn labels_from_deployment_records() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (Address::repeat_byte(0xaa), Address::repeat_byte(0xbb));
        let f1 = dir.path().join("8018.json");
        std::fs::write(
            &f1,
            json!({ "chainId": 8018, "contracts": { "PoolManager": a } }).to_string(),
        )
        .unwrap();
        let f2 = dir.path().join("names.json");
        std::fs::write(&f2, json!({ b.to_string(): "Faucet" }).to_string()).unwrap();
        assert_eq!(load_labels(&[f1, f2]).unwrap(), 2);
        assert_eq!(label(&a).as_deref(), Some("PoolManager"));
        assert_eq!(label(&b).as_deref(), Some("Faucet"));
        assert_eq!(label(&STAKING).as_deref(), Some("StakingManager"));
    }
}
