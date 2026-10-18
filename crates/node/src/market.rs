//! Explorer API for the markets: AI inference (`/api/compute…`, ADR 0011) and TEE leases
//! (`/api/tee…`, ADR 0013). Read-only views of the contracts, plus block hosting so the page can
//! post a compute job it sealed in the browser.

use crate::explorer::{ApiResult, Explorer, internal, not_found};
use alloy_primitives::{Address, U256, hex};
use alloy_sol_types::SolCall;
use bolt_ipld::Cid;
use bolt_store::{RO, StateView, Tx};
use bolt_system::{abi::*, addresses::*, queries};
use serde_json::{Value, json};

const MAX: u64 = 50;
/// Jobs scanned to find providers and a requester's jobs.
const SCAN: u64 = 500;

fn bad(msg: impl Into<String>) -> (u16, String) {
    (400, msg.into())
}

fn cid_text(b: &[u8]) -> String {
    if b.is_empty() {
        return String::new();
    }
    Cid::try_from(b).map(|c| c.to_string()).unwrap_or_else(|_| hex::encode_prefixed(b))
}

fn limit(query: &str) -> u64 {
    crate::explorer::query_param(query, "limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(25)
        .clamp(1, MAX)
}

fn job_state(s: u8) -> &'static str {
    match s {
        1 => "open",
        2 => "accepted",
        3 => "delivered",
        4 => "disputed",
        5 => "settled",
        6 => "refunded",
        _ => "?",
    }
}

impl Explorer {
    fn v<C: SolCall>(&self, r: &Tx<'_, RO>, to: Address, c: C) -> Result<C::Return, (u16, String)> {
        queries::call(&StateView::latest(r), self.chain.config().chain_id, to, c).map_err(internal)
    }

    fn deployed(&self, r: &Tx<'_, RO>, a: Address) -> bool {
        r.account(&a)
            .ok()
            .flatten()
            .is_some_and(|acc| acc.code_hash != alloy_primitives::KECCAK256_EMPTY)
    }

    fn job_json(&self, id: u64, j: &IComputeMarket::Job) -> Value {
        json!({
            "id": id,
            "requester": j.requester,
            "provider": j.provider,
            "state": job_state(j.state),
            "model": j.model,
            "deadline": j.deadline,
            "deliveredAt": j.deliveredAt,
            "window": j.window,
            "tokensIn": j.tokensIn,
            "tokensOut": j.tokensOut,
            "maxIn": j.maxIn,
            "maxOut": j.maxOut,
            "priceIn": j.priceIn.to_string(),
            "priceOut": j.priceOut.to_string(),
            "relayFee": j.relayFee.to_string(),
            "escrow": j.escrow.to_string(),
            "input": cid_text(&j.input),
            "output": cid_text(&j.output),
        })
    }

    /// `GET /api/compute[?limit=n&requester=0x…]`: models, recent jobs, providers seen.
    pub(crate) fn compute(&self, r: &Tx<'_, RO>, query: &str) -> ApiResult {
        if !self.deployed(r, COMPUTE) {
            return Ok(json!({ "enabled": false }));
        }
        let mut models = Vec::new();
        if self.deployed(r, MODELS) {
            let n = self.v(r, MODELS, IModelRegistry::modelCountCall {})?.to::<u64>();
            for id in 1..=n.min(200) {
                let m = self.v(r, MODELS, IModelRegistry::modelCall { id })?;
                let providers = self.v(r, MODELS, IModelRegistry::providerCountCall { id })?;
                models.push(json!({
                    "id": id, "name": m.name, "weights": cid_text(&m.weights), "runtime": m.runtime,
                    "parameters": m.parameters, "vramMiB": m.vramMiB, "providers": providers,
                    "registrant": m.registrant,
                }));
            }
        }
        let count = self.v(r, COMPUTE, IComputeMarket::jobCountCall {})?.to::<u64>();
        let want = limit(query);
        let requester: Option<Address> =
            crate::explorer::query_param(query, "requester").and_then(|a| a.parse().ok());
        let mut jobs = Vec::new();
        let mut providers: Vec<Address> = self.registered_providers(r);
        // Recent prices per model (for the page's suggested prices).
        let mut prices: std::collections::HashMap<u64, (Vec<u128>, Vec<u128>)> = Default::default();
        for id in (count.saturating_sub(SCAN)..count).rev() {
            let j = self.v(r, COMPUTE, IComputeMarket::jobCall { id: U256::from(id) })?;
            if j.provider != Address::ZERO && !providers.contains(&j.provider) {
                providers.push(j.provider);
            }
            if matches!(j.state, 3 | 5) {
                let e = prices.entry(j.model).or_default();
                if e.0.len() < 50 {
                    e.0.push(j.priceIn);
                    e.1.push(j.priceOut);
                }
            }
            if (jobs.len() as u64) < want && requester.is_none_or(|a| a == j.requester) {
                jobs.push(self.job_json(id, &j));
            }
        }
        let median = |v: &mut Vec<u128>| -> Option<String> {
            v.sort_unstable();
            v.get(v.len() / 2).map(|x| x.to_string())
        };
        for m in models.iter_mut() {
            let id = m["id"].as_u64().unwrap_or(0);
            if let Some((pi, po)) = prices.get_mut(&id) {
                m["priceIn"] = json!(median(pi));
                m["priceOut"] = json!(median(po));
            }
        }
        let model_ids: Vec<u64> = models.iter().filter_map(|m| m["id"].as_u64()).collect();
        let mut provs = Vec::new();
        for p in providers {
            let i = self.v(r, COMPUTE, IComputeMarket::providerCall { p })?;
            let key = self.v(r, COMPUTE, IComputeMarket::encryptionKeyCall { account: p })?;
            let mut serves = Vec::new();
            for id in &model_ids {
                if self.v(r, MODELS, IModelRegistry::servesCall { id: *id, provider: p })? {
                    serves.push(*id);
                }
            }
            let limit = self.v(r, COMPUTE, IComputeMarket::jobLimitCall { p })?;
            provs.push(json!({
                "address": p, "registered": i.registered, "bond": i.bond.to_string(),
                "jobsDone": i.jobsDone, "faults": i.faults, "exitEpoch": i.exitEpoch,
                "encKey": key, "models": serves, "jobLimit": limit.to_string(),
            }));
        }
        let disputes = self.v(r, COMPUTE, IComputeMarket::pendingDisputesCall {})?.len();
        Ok(json!({
            "enabled": true, "contract": COMPUTE, "models": models, "jobs": jobs,
            "providers": provs, "jobCount": count, "pendingDisputes": disputes,
        }))
    }

    /// Accounts that registered as providers or declared a model, from the address index (the
    /// most recent transactions to `ComputeMarket` and `ModelRegistry`).
    fn registered_providers(&self, r: &Tx<'_, RO>) -> Vec<Address> {
        use alloy_consensus::Transaction as _;
        let mut out: Vec<Address> = Vec::new();
        if r.address_index_from().ok().flatten().is_none() {
            return out;
        }
        let reg = IComputeMarket::registerCall::SELECTOR;
        let reg_for = IComputeMarket::registerForCall::SELECTOR;
        let support = IModelRegistry::setSupportCall::SELECTOR;
        for contract in [COMPUTE, MODELS] {
            let Ok(entries) = r.address_txs(&contract, None, 2000) else { continue };
            for e in entries {
                let Ok(Some(b)) = r.block(e.block) else { continue };
                let Some(tx) = b.transactions.get(e.index as usize) else { continue };
                if tx.to() != Some(contract) {
                    continue;
                }
                let input = tx.input();
                if input.len() < 4 {
                    continue;
                }
                let sel: [u8; 4] = input[..4].try_into().expect("4 bytes");
                let who = if sel == reg || sel == support {
                    b.senders.get(e.index as usize).copied()
                } else if sel == reg_for {
                    IComputeMarket::registerForCall::abi_decode(input).ok().map(|c| c.provider_)
                } else {
                    None
                };
                if let Some(a) = who
                    && !out.contains(&a)
                {
                    out.push(a);
                }
            }
        }
        out
    }

    /// `GET /api/compute/job/<id>`.
    pub(crate) fn compute_job(&self, r: &Tx<'_, RO>, id: &str) -> ApiResult {
        let id: u64 = id.parse().map_err(|_| bad("job id"))?;
        let count = self.v(r, COMPUTE, IComputeMarket::jobCountCall {})?.to::<u64>();
        if id >= count {
            return Err(not_found("no such job"));
        }
        let j = self.v(r, COMPUTE, IComputeMarket::jobCall { id: U256::from(id) })?;
        let mut out = self.job_json(id, &j);
        let rl = self.v(r, COMPUTE, IComputeMarket::relaysCall { id: U256::from(id) })?;
        out["relays"] = json!({
            "acceptRelayer": rl.acceptRelayer, "acceptFee": rl.acceptFee.to_string(),
            "deliverRelayer": rl.deliverRelayer, "deliverFee": rl.deliverFee.to_string(),
        });
        if j.state == 4 {
            let d = self.v(r, COMPUTE, IComputeMarket::disputesCall { id: U256::from(id) })?;
            out["dispute"] = json!({ "openedAt": d.openedAt, "panelEpoch": d.panelEpoch });
        }
        if self.deployed(r, MODELS) && j.model != 0 {
            let m = self.v(r, MODELS, IModelRegistry::modelCall { id: j.model })?;
            out["modelName"] = json!(m.name);
        }
        let bal = self.v(r, COMPUTE, IComputeMarket::balanceOfCall { account: j.requester })?;
        out["requesterBalance"] = json!(bal.to_string());
        Ok(out)
    }

    /// `GET /api/compute/blocks?cids=a,b&root=r`: blocks of a sealed job file (fetched from the
    /// network when this node lacks them), hex.
    pub(crate) fn compute_blocks(&self, query: &str) -> ApiResult {
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| (503, "this node does not host blocks".to_string()))?;
        let cids: Vec<String> = crate::explorer::query_param(query, "cids")
            .unwrap_or("")
            .split(',')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        if cids.is_empty() || cids.len() > 64 {
            return Err(bad("1 to 64 CIDs"));
        }
        let root = crate::explorer::query_param(query, "root").map(str::to_string);
        let got = host.fetch(cids.clone(), None, root).map_err(|e| (404, e))?;
        Ok(json!({ "blocks": got.iter().map(hex::encode).collect::<Vec<_>>() }))
    }

    /// `POST /api/compute/host` `{ "root": cid, "blocks": [[cid, hex]…] }`: keeps a sealed job
    /// file's blocks (each checked against its CID) and announces it to storage providers.
    pub(crate) fn compute_host(&self, body: &[u8]) -> ApiResult {
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| (503, "this node does not host blocks".to_string()))?;
        let v: Value = serde_json::from_slice(body).map_err(|e| bad(e.to_string()))?;
        let root = v["root"].as_str().ok_or_else(|| bad("root"))?.to_string();
        let mut blocks = Vec::new();
        for b in v["blocks"].as_array().ok_or_else(|| bad("blocks"))? {
            let cid = b[0].as_str().ok_or_else(|| bad("block CID"))?.to_string();
            let data = hex::decode(b[1].as_str().ok_or_else(|| bad("block data"))?)
                .map_err(|_| bad("block hex"))?;
            blocks.push((cid, data));
        }
        if blocks.is_empty() || blocks.len() > 64 {
            return Err(bad("1 to 64 blocks"));
        }
        host.host(root, blocks).map_err(bad)?;
        Ok(json!({ "ok": true }))
    }

    fn machine_json(&self, r: &Tx<'_, RO>, m: u64) -> ApiResult {
        let mc = self.v(r, LEASES, IEnclaveLease::machineCall { m })?;
        let o = self.v(r, LEASES, IEnclaveLease::operatorsCall { operator: mc.operator })?;
        let black =
            self.v(r, LEASES, IEnclaveLease::blacklistedCall { machineId: mc.machineId })?;
        Ok(json!({
            "id": m, "operator": mc.operator, "kind": if mc.kind == 1 { "tdx" } else { "tpm" },
            "verified": mc.verified, "available": mc.available, "tcbStatus": mc.tcbStatus,
            "pricePerHour": mc.pricePerHour.to_string(), "machineId": mc.machineId,
            "cpus": mc.cpus, "memGiB": mc.memGiB, "gpu": mc.gpu, "endpoint": mc.endpoint,
            "leases": mc.leases, "registeredAt": mc.registeredAt, "blacklisted": black,
            "bond": o.bond.to_string(), "slashedAt": o.slashedAt,
        }))
    }

    fn lease_json(&self, id: u64, l: &IEnclaveLease::Lease) -> Value {
        let state = match l.state {
            1 => "pending",
            2 => "verifying",
            3 => "active",
            4 => "ended",
            _ => "?",
        };
        json!({
            "id": id, "renter": l.renter, "machine": l.machine, "image": l.image, "state": state,
            "degraded": l.degraded, "minTcb": l.minTcb, "pricePerHour": l.pricePerHour.to_string(),
            "escrow": l.escrow.to_string(), "relayFee": l.relayFee.to_string(),
            "minBond": l.minBond.to_string(), "agentHash": l.agentHash, "signer": l.signer,
            "encKey": l.encKey, "version": l.version, "activatedAt": l.activatedAt,
            "lastCheckpointAt": l.lastCheckpointAt, "hoursPaid": l.hoursPaid, "exitAt": l.exitAt,
            "stateRoot": l.stateRoot, "stateCid": String::from_utf8_lossy(&l.stateCid),
        })
    }

    /// `GET /api/tee[?limit=n]`: machines, recent leases, images, collateral.
    pub(crate) fn tee(&self, r: &Tx<'_, RO>, query: &str) -> ApiResult {
        if !self.deployed(r, LEASES) {
            return Ok(json!({ "enabled": false }));
        }
        let n = self.v(r, LEASES, IEnclaveLease::machineCountCall {})?.to::<u64>();
        let mut machines = Vec::new();
        for m in (1..=n).rev().take(200) {
            machines.push(self.machine_json(r, m)?);
        }
        let count = self.v(r, LEASES, IEnclaveLease::leaseCountCall {})?.to::<u64>();
        let mut leases = Vec::new();
        for id in (1..=count).rev().take(limit(query) as usize) {
            let l = self.v(r, LEASES, IEnclaveLease::leaseCall { id: U256::from(id) })?;
            leases.push(self.lease_json(id, &l));
        }
        let mut images = Vec::new();
        let ni = self.v(r, IMAGES, IImageRegistry::imageCountCall {})?.to::<u64>();
        for id in 1..=ni.min(100) {
            let i = self.v(r, IMAGES, IImageRegistry::imageCall { id })?;
            let mut ms = Vec::new();
            for m in self.v(r, IMAGES, IImageRegistry::measurementsOfCall { id })? {
                let d = self.v(r, IMAGES, IImageRegistry::measurementCall { id, m })?;
                ms.push(json!({ "hash": m, "kind": if d.kind == 1 { "tdx" } else if d.kind == 3 { "tpm" } else { "snp" }, "platform": d.platform, "reproductions": d.reproductions }));
            }
            images.push(json!({
                "id": id, "name": i.name, "source": String::from_utf8_lossy(&i.source),
                "build": i.build, "registrant": i.registrant, "measurements": ms,
            }));
        }
        let root = self.v(r, COLLATERAL, ITeeCollateral::rootCall {})?;
        let qe = self.v(r, COLLATERAL, ITeeCollateral::qeIdentityCall {})?;
        let intel = root.x.0 == bolt_attest::intel::INTEL_ROOT.0;
        Ok(json!({
            "enabled": true, "contract": LEASES, "machines": machines, "leases": leases,
            "leaseCount": count, "images": images,
            "pendingAttestations": self.v(r, LEASES, IEnclaveLease::pendingAttestationsCall {})?.len(),
            "burned": self.v(r, LEASES, IEnclaveLease::burnedCall {})?.to_string(),
            "collateral": {
                "root": if intel { "intel" } else { "simulated" },
                "qeEvaluation": qe.evaluation, "qeNextUpdate": qe.nextUpdate,
            },
        }))
    }

    /// `GET /api/tee/lease/<id>`.
    pub(crate) fn tee_lease(&self, r: &Tx<'_, RO>, id: &str) -> ApiResult {
        let id: u64 = id.parse().map_err(|_| bad("lease id"))?;
        let count = self.v(r, LEASES, IEnclaveLease::leaseCountCall {})?.to::<u64>();
        if id == 0 || id > count {
            return Err(not_found("no such lease"));
        }
        let l = self.v(r, LEASES, IEnclaveLease::leaseCall { id: U256::from(id) })?;
        let mut out = self.lease_json(id, &l);
        out["machineInfo"] = self.machine_json(r, l.machine)?;
        Ok(out)
    }

    /// `GET /api/tee/machine/<id>`: a machine and its leases (most recent 200 scanned).
    pub(crate) fn tee_machine(&self, r: &Tx<'_, RO>, id: &str) -> ApiResult {
        let m: u64 = id.parse().map_err(|_| bad("machine id"))?;
        let n = self.v(r, LEASES, IEnclaveLease::machineCountCall {})?.to::<u64>();
        if m == 0 || m > n {
            return Err(not_found("no such machine"));
        }
        let mut out = self.machine_json(r, m)?;
        let count = self.v(r, LEASES, IEnclaveLease::leaseCountCall {})?.to::<u64>();
        let mut leases = Vec::new();
        for id in (1..=count).rev().take(200) {
            let l = self.v(r, LEASES, IEnclaveLease::leaseCall { id: U256::from(id) })?;
            if l.machine == m {
                leases.push(self.lease_json(id, &l));
            }
        }
        out["leaseList"] = json!(leases);
        Ok(out)
    }
}
