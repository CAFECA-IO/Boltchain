//! `eth_*` JSON-RPC subset for wallets (MetaMask) and tooling (Foundry, viem, ethers).
//!
//! State queries accept `latest`/`pending`/`safe`/`finalized` (all served from the head until
//! finality lands in M3) and explicit block numbers or hashes within the last
//! [`bolt_store::HISTORY_BLOCKS`] blocks.

mod call;
mod convert;

use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{Address, B256, Bytes, U64, U256};
use alloy_rpc_types_eth::{FeeHistory, Filter, TransactionRequest};
use bolt_chain::Chain;
use bolt_store::{RO, StateView, Tx};
use bolt_txpool::{AccountState, TxPool};
use jsonrpsee::{
    RpcModule,
    server::{Server, ServerHandle},
    types::{ErrorObjectOwned, Params},
};
use std::{net::SocketAddr, sync::Arc};

/// Suggested priority fee: 0.01 gwei.
pub const DEFAULT_PRIORITY_FEE: u128 = 10_000_000;

/// Maximum block range for `eth_getLogs`.
pub const MAX_LOG_RANGE: u64 = 10_000;

/// Shared state for RPC handlers.
#[derive(Debug)]
pub struct RpcContext {
    /// The chain.
    pub chain: Arc<Chain>,
    /// The transaction pool.
    pub pool: Arc<TxPool>,
    /// Reported by `web3_clientVersion`.
    pub client_version: String,
    /// When set (on non-producing nodes), `eth_sendRawTransaction` hands transactions to this
    /// forwarder instead of the local pool.
    pub forwarder: Option<Arc<dyn TxForwarder>>,
    /// Block hosting for SwarmStorage deals (ADR 0014): `bolt_hostBlocks` / `bolt_getBlocks`.
    /// `None`: the methods answer with an error (the node was started without `--rpc-storage`).
    pub host: Option<Arc<dyn BlockHost>>,
    /// Submits signed actions of accounts without BOLT (`bolt_relay`, ADR 0011 / 0013): the
    /// node pays the gas and the action pays it a fee. `None`: relaying is off.
    pub relay: Option<Arc<dyn CallRelay>>,
}

/// Sends calls on behalf of others from the node's relay account (`bolt_relay`).
pub trait CallRelay: Send + Sync + std::fmt::Debug + 'static {
    /// Checks that `data` to `to` is a call this relay accepts (a known action paying at least
    /// its minimum fee) and would succeed, then sends it; returns the transaction hash.
    fn relay(&self, to: Address, data: Vec<u8>) -> Result<B256, String>;
}

/// Stores and fetches IPFS blocks for a user's SwarmStorage deals (ADR 0014).
pub trait BlockHost: Send + Sync + std::fmt::Debug + 'static {
    /// Stores `blocks` (each checked against its CID) and announces deal index `root` to storage
    /// providers.
    fn host(&self, root: String, blocks: Vec<(String, Vec<u8>)>) -> Result<(), String>;
    /// Reads blocks, fetching missing ones from the network: from deal `deal`'s providers and the
    /// announced source of `root` first.
    fn fetch(
        &self,
        cids: Vec<String>,
        deal: Option<u64>,
        root: Option<String>,
    ) -> Result<Vec<Vec<u8>>, String>;
    /// Verifier encryption keys (hex) announced by validators `ids` (ADR 0011), in order.
    fn verifier_keys(&self, ids: Vec<u32>) -> Vec<Option<String>>;
    /// Accepts the requester's re-encryption of a disputed job's files for the verifier panel
    /// (envelope CIDs and the requester's signature) and gossips it.
    fn share_dispute(&self, job: u64, envelopes: [String; 3], sig: Vec<u8>) -> Result<(), String>;
}

/// Forwards raw transactions to the block producer.
pub trait TxForwarder: Send + Sync + std::fmt::Debug + 'static {
    /// Forwards and returns the transaction hash or the producer's rejection.
    fn forward(&self, raw: Vec<u8>) -> Result<B256, String>;
}

pub(crate) type RpcResult<T> = Result<T, ErrorObjectOwned>;

pub(crate) fn err(code: i32, msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, msg.into(), None::<()>)
}

pub(crate) fn internal(e: impl std::fmt::Display) -> ErrorObjectOwned {
    err(-32000, e.to_string())
}

/// Latest-state view used for transaction-pool admission.
#[derive(Debug)]
pub struct HeadState<'a, 'e>(pub &'a Tx<'e, RO>);

impl AccountState for HeadState<'_, '_> {
    fn nonce_balance(&self, addr: &Address) -> (u64, U256) {
        self.0.account(addr).ok().flatten().map(|a| (a.nonce, a.balance)).unwrap_or_default()
    }
}

impl RpcContext {
    /// Resolves a block id to a number, `None` meaning "latest".
    pub(crate) fn resolve(&self, r: &Tx<'_, RO>, id: Option<BlockId>) -> RpcResult<Option<u64>> {
        let head = r.head().map_err(internal)?.unwrap_or(0);
        let n = match id {
            None => return Ok(None),
            Some(BlockId::Number(tag)) => match tag {
                BlockNumberOrTag::Latest
                | BlockNumberOrTag::Pending
                | BlockNumberOrTag::Safe
                | BlockNumberOrTag::Finalized => return Ok(None),
                BlockNumberOrTag::Earliest => 0,
                BlockNumberOrTag::Number(n) => n,
            },
            Some(BlockId::Hash(h)) => r
                .block_number(&h.block_hash)
                .map_err(internal)?
                .ok_or_else(|| err(-32001, "block not found"))?,
        };
        if n > head {
            return Err(err(-32001, format!("block {n} not found (head {head})")));
        }
        Ok(if n == head { None } else { Some(n) })
    }

    pub(crate) fn view<'a, 'e>(
        &self,
        r: &'a Tx<'e, RO>,
        at: Option<u64>,
    ) -> RpcResult<StateView<'a, 'e, RO>> {
        match at {
            None => Ok(StateView::latest(r)),
            Some(n) => StateView::at(r, n).map_err(|_| {
                err(
                    -32000,
                    format!(
                        "state for block {n} is pruned (only the last {} blocks are kept)",
                        bolt_store::HISTORY_BLOCKS
                    ),
                )
            }),
        }
    }
}

fn block_number_param(tag: BlockNumberOrTag, head: u64) -> u64 {
    match tag {
        BlockNumberOrTag::Number(n) => n,
        BlockNumberOrTag::Earliest => 0,
        _ => head,
    }
}

/// Builds the RPC module.
pub fn module(ctx: RpcContext) -> RpcModule<RpcContext> {
    let mut m = RpcModule::new(ctx);
    macro_rules! method {
        ($name:literal, |$p:pat_param, $c:pat_param| -> $ret:ty $body:block) => {{
            fn handler($p: Params<'_>, $c: &RpcContext) -> $ret $body
            m.register_blocking_method($name, |p, c, _| handler(p, &c)).expect("unique method name");
        }};
    }

    method!("web3_clientVersion", |_, c| -> RpcResult<String> { Ok(c.client_version.clone()) });
    method!("net_version", |_, c| -> RpcResult<String> {
        Ok(c.chain.config().chain_id.to_string())
    });
    method!("net_listening", |_, _| -> RpcResult<bool> { Ok(true) });
    method!("net_peerCount", |_, _| -> RpcResult<U64> {
        Ok(U64::from(bolt_primitives::metrics::PEERS.get()))
    });
    method!("eth_syncing", |_, _| -> RpcResult<bool> { Ok(false) });
    method!("eth_accounts", |_, _| -> RpcResult<Vec<Address>> { Ok(vec![]) });
    method!("eth_chainId", |_, c| -> RpcResult<U64> { Ok(U64::from(c.chain.config().chain_id)) });
    method!("eth_blockNumber", |_, c| -> RpcResult<U64> {
        Ok(U64::from(
            c.chain.store().reader().map_err(internal)?.head().map_err(internal)?.unwrap_or(0),
        ))
    });
    method!("eth_gasPrice", |_, c| -> RpcResult<U256> {
        Ok(U256::from(
            u128::from(c.chain.next_base_fee().map_err(internal)?) + DEFAULT_PRIORITY_FEE,
        ))
    });
    method!("eth_maxPriorityFeePerGas", |_, _| -> RpcResult<U256> {
        Ok(U256::from(DEFAULT_PRIORITY_FEE))
    });
    method!("eth_blobBaseFee", |_, _| -> RpcResult<U256> {
        Err(err(-32601, "blob transactions are not supported on Boltchain"))
    });

    method!("eth_getBalance", |p, c| -> RpcResult<U256> {
        let (addr, id): (Address, Option<BlockId>) = with_block(&p)?;
        let r = c.chain.store().reader().map_err(internal)?;
        let at = c.resolve(&r, id)?;
        let acc = match at {
            None => r.account(&addr).map_err(internal)?,
            Some(n) => r
                .account_at(&addr, n)
                .map_err(internal)?
                .ok_or_else(|| err(-32000, "state pruned"))?,
        };
        Ok(acc.map(|a| a.balance).unwrap_or_default())
    });
    method!("eth_getTransactionCount", |p, c| -> RpcResult<U64> {
        let (addr, id): (Address, Option<BlockId>) = with_block(&p)?;
        let pending = matches!(id, Some(BlockId::Number(BlockNumberOrTag::Pending)));
        let r = c.chain.store().reader().map_err(internal)?;
        let at = c.resolve(&r, id)?;
        let acc = match at {
            None => r.account(&addr).map_err(internal)?,
            Some(n) => r
                .account_at(&addr, n)
                .map_err(internal)?
                .ok_or_else(|| err(-32000, "state pruned"))?,
        };
        let nonce = acc.map(|a| a.nonce).unwrap_or_default();
        Ok(U64::from(if pending { c.pool.pending_nonce(&addr, nonce) } else { nonce }))
    });
    method!("eth_getCode", |p, c| -> RpcResult<Bytes> {
        let (addr, id): (Address, Option<BlockId>) = with_block(&p)?;
        let r = c.chain.store().reader().map_err(internal)?;
        let at = c.resolve(&r, id)?;
        let acc = match at {
            None => r.account(&addr).map_err(internal)?,
            Some(n) => r
                .account_at(&addr, n)
                .map_err(internal)?
                .ok_or_else(|| err(-32000, "state pruned"))?,
        };
        match acc {
            Some(a) => Ok(r.code(&a.code_hash).map_err(internal)?.unwrap_or_default()),
            None => Ok(Bytes::new()),
        }
    });
    method!("eth_getStorageAt", |p, c| -> RpcResult<B256> {
        let mut seq = p.sequence();
        let (addr, slot): (Address, U256) = (seq.next()?, seq.next()?);
        let id: Option<BlockId> = seq.optional_next()?;
        let r = c.chain.store().reader().map_err(internal)?;
        let at = c.resolve(&r, id)?;
        let slot = B256::from(slot);
        let v = match at {
            None => r.storage(&addr, &slot).map_err(internal)?,
            Some(n) => r
                .storage_at(&addr, &slot, n)
                .map_err(internal)?
                .ok_or_else(|| err(-32000, "state pruned"))?,
        };
        Ok(B256::from(v))
    });

    method!("eth_getProof", |p,
                             c|
     -> RpcResult<alloy_rpc_types_eth::EIP1186AccountProofResponse> {
        let mut seq = p.sequence();
        let (addr, keys): (Address, Vec<alloy_serde::storage::JsonStorageKey>) =
            (seq.next()?, seq.next()?);
        let id: Option<BlockId> = seq.optional_next()?;
        let r = c.chain.store().reader().map_err(internal)?;
        if let Some(n) = c.resolve(&r, id)? {
            return Err(err(
                -32000,
                format!("eth_getProof serves the latest state only (block {n} is not the head)"),
            ));
        }
        get_proof(&r, addr, keys).map_err(internal)
    });
    method!("eth_call", |p, c| -> RpcResult<Bytes> {
        let (req, id): (TransactionRequest, Option<BlockId>) = with_block(&p)?;
        call::eth_call(c, req, id)
    });
    method!("eth_estimateGas", |p, c| -> RpcResult<U64> {
        let (req, id): (TransactionRequest, Option<BlockId>) = with_block(&p)?;
        call::estimate_gas(c, req, id).map(U64::from)
    });
    method!("eth_sendRawTransaction", |p, c| -> RpcResult<B256> {
        let (raw,): (Bytes,) = p.parse()?;
        if let Some(f) = &c.forwarder {
            return f.forward(raw.to_vec()).map_err(|e| err(-32000, e));
        }
        let r = c.chain.store().reader().map_err(internal)?;
        c.pool.add_raw(&raw, &HeadState(&r)).map_err(|e| err(-32000, e.to_string()))
    });

    method!("bolt_hostBlocks", |p, c| -> RpcResult<bool> {
        let (root, blocks): (String, Vec<(String, Bytes)>) = p.parse()?;
        let h =
            c.host.as_ref().ok_or_else(|| err(-32601, "block hosting is off (--rpc-storage)"))?;
        h.host(root, blocks.into_iter().map(|(c, b)| (c, b.to_vec())).collect())
            .map_err(|e| err(-32000, e))?;
        Ok(true)
    });
    method!("bolt_getBlocks", |p, c| -> RpcResult<Vec<Bytes>> {
        let mut seq = p.sequence();
        let cids: Vec<String> = seq.next()?;
        let deal: Option<u64> = seq.optional_next()?.flatten();
        let root: Option<String> = seq.optional_next()?.flatten();
        let h =
            c.host.as_ref().ok_or_else(|| err(-32601, "block hosting is off (--rpc-storage)"))?;
        if cids.len() > 256 {
            return Err(err(-32602, "at most 256 blocks per call"));
        }
        let got = h.fetch(cids, deal, root).map_err(|e| err(-32000, e))?;
        Ok(got.into_iter().map(Bytes::from).collect())
    });

    method!("bolt_relay", |p, c| -> RpcResult<B256> {
        let (to, data): (Address, Bytes) = p.parse()?;
        let r = c.relay.as_ref().ok_or_else(|| err(-32601, "this node does not relay"))?;
        r.relay(to, data.to_vec()).map_err(|e| err(-32000, e))
    });

    method!("bolt_verifierKeys", |p, c| -> RpcResult<Vec<Option<String>>> {
        let (ids,): (Vec<u32>,) = p.parse()?;
        let h =
            c.host.as_ref().ok_or_else(|| err(-32601, "block hosting is off (--rpc-storage)"))?;
        Ok(h.verifier_keys(ids))
    });
    method!("bolt_shareDispute", |p, c| -> RpcResult<bool> {
        let (job, input, output, reason, sig): (U64, String, String, String, Bytes) = p.parse()?;
        let h =
            c.host.as_ref().ok_or_else(|| err(-32601, "block hosting is off (--rpc-storage)"))?;
        h.share_dispute(job.to::<u64>(), [input, output, reason], sig.to_vec())
            .map_err(|e| err(-32000, e))?;
        Ok(true)
    });

    method!("eth_getBlockByNumber", |p, c| -> RpcResult<Option<serde_json::Value>> {
        let (tag, full): (BlockNumberOrTag, bool) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        let head = r.head().map_err(internal)?.unwrap_or(0);
        convert::block_json(&r, block_number_param(tag, head), full)
    });
    method!("eth_getBlockByHash", |p, c| -> RpcResult<Option<serde_json::Value>> {
        let (hash, full): (B256, bool) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        match r.block_number(&hash).map_err(internal)? {
            Some(n) => convert::block_json(&r, n, full),
            None => Ok(None),
        }
    });
    method!("eth_getBlockTransactionCountByNumber", |p, c| -> RpcResult<Option<U64>> {
        let (tag,): (BlockNumberOrTag,) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        let head = r.head().map_err(internal)?.unwrap_or(0);
        Ok(r.block(block_number_param(tag, head))
            .map_err(internal)?
            .map(|b| U64::from(b.transactions.len())))
    });
    method!("eth_getTransactionByHash", |p, c| -> RpcResult<Option<serde_json::Value>> {
        let (hash,): (B256,) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        if let Some(v) = convert::mined_tx_json(&r, &hash)? {
            return Ok(Some(v));
        }
        Ok(c.pool.get(&hash).map(|p| convert::pending_tx_json(&p.tx, p.sender)))
    });
    method!("eth_getTransactionReceipt", |p, c| -> RpcResult<Option<serde_json::Value>> {
        let (hash,): (B256,) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        convert::receipt_json(&r, &hash)
    });
    method!("eth_getBlockReceipts", |p, c| -> RpcResult<Option<Vec<serde_json::Value>>> {
        let (tag,): (BlockNumberOrTag,) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        let head = r.head().map_err(internal)?.unwrap_or(0);
        convert::block_receipts_json(&r, block_number_param(tag, head))
    });
    method!("eth_getLogs", |p, c| -> RpcResult<Vec<serde_json::Value>> {
        let (filter,): (Filter,) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        convert::logs(&r, &filter)
    });
    method!("eth_feeHistory", |p, c| -> RpcResult<FeeHistory> {
        let (count, newest, pct): (U64, BlockNumberOrTag, Option<Vec<f64>>) = p.parse()?;
        let r = c.chain.store().reader().map_err(internal)?;
        let head = r.head().map_err(internal)?.unwrap_or(0);
        let newest = block_number_param(newest, head).min(head);
        let count = count.to::<u64>().clamp(1, 1024).min(newest + 1);
        let oldest = newest + 1 - count;
        let mut fh = FeeHistory { oldest_block: oldest, ..Default::default() };
        for n in oldest..=newest {
            let h = r.header(n).map_err(internal)?.ok_or_else(|| internal("missing header"))?;
            fh.base_fee_per_gas.push(u128::from(h.base_fee_per_gas.unwrap_or_default()));
            fh.gas_used_ratio.push(h.gas_used as f64 / h.gas_limit.max(1) as f64);
            fh.base_fee_per_blob_gas.push(0);
            fh.blob_gas_used_ratio.push(0.0);
        }
        let last = r.header(newest).map_err(internal)?.ok_or_else(|| internal("missing header"))?;
        fh.base_fee_per_gas
            .push(u128::from(bolt_exec::next_base_fee(&last, c.chain.config().min_base_fee_wei)));
        fh.base_fee_per_blob_gas.push(0);
        if let Some(k) = pct.as_ref().map(Vec::len).filter(|k| *k > 0) {
            fh.reward = Some(vec![vec![DEFAULT_PRIORITY_FEE; k]; count as usize]);
        }
        Ok(fh)
    });
    m
}

/// EIP-1186 proof of `addr` and its `keys` in the latest state of `r` (the head block's
/// `stateRoot`). Proofs of older states are not available: the tries keep only the latest nodes.
pub fn get_proof(
    r: &Tx<'_, RO>,
    addr: Address,
    keys: Vec<alloy_serde::storage::JsonStorageKey>,
) -> bolt_store::Result<alloy_rpc_types_eth::EIP1186AccountProofResponse> {
    let acc = r.account(&addr)?;
    let account_proof = r.account_proof(&addr)?;
    let mut storage_proof = Vec::with_capacity(keys.len());
    for key in keys {
        let slot = key.as_b256();
        let (value, proof) = match &acc {
            Some(a) if a.storage_root != alloy_trie::EMPTY_ROOT_HASH => {
                (r.storage(&addr, &slot)?, r.storage_proof(&addr, &slot)?)
            }
            _ => (U256::ZERO, vec![]),
        };
        storage_proof.push(alloy_rpc_types_eth::EIP1186StorageProof { key, value, proof });
    }
    let acc = acc.unwrap_or_default();
    Ok(alloy_rpc_types_eth::EIP1186AccountProofResponse {
        address: addr,
        balance: acc.balance,
        code_hash: acc.code_hash,
        nonce: acc.nonce,
        storage_hash: acc.storage_root,
        account_proof,
        storage_proof,
    })
}

/// Starts the HTTP JSON-RPC server (with permissive CORS for browser wallets).
pub async fn start(
    addr: SocketAddr,
    ctx: RpcContext,
) -> std::io::Result<(SocketAddr, ServerHandle)> {
    let cors = tower_http::cors::CorsLayer::permissive();
    let server = Server::builder()
        .set_http_middleware(tower::ServiceBuilder::new().layer(cors))
        .build(addr)
        .await?;
    let local = server.local_addr()?;
    let handle = server.start(module(ctx));
    Ok((local, handle))
}

/// Parses `[value, block?]`: the block parameter may be omitted (clients such as ethers and
/// MetaMask leave it out of `eth_estimateGas`; geth treats a missing tag as `latest`).
fn with_block<T: serde::de::DeserializeOwned>(p: &Params<'_>) -> RpcResult<(T, Option<BlockId>)> {
    let mut seq = p.sequence();
    let v: T = seq.next()?;
    Ok((v, seq.optional_next()?))
}
