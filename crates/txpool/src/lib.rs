//! Transaction pool with Boltchain admission rules.
//!
//! Admission: EIP-155 replay protection with the chain's id, no blob transactions, gas limit
//! within both the EIP-7825 cap and the block gas limit, fee cap at least the minimum base fee,
//! nonce not below the account nonce, balance covering the maximum cost, at most
//! [`PoolConfig::max_per_sender`] transactions per sender, and a 10% tip bump to replace.
//!
//! Eviction (at every new block): transactions below the account nonce (included), transactions
//! older than [`PoolConfig::max_age`], and a sender's next transaction once the balance no longer
//! covers it. A transaction that never executes would otherwise stay forever: the sender's later
//! nonces queue behind it until the per-sender limit refuses new ones ("nonce too high"), and the
//! "pending" nonce keeps counting transactions that will never be mined.
//!
//! From M2 the node forwards admitted transactions to the next few slot leaders instead of
//! flooding them over gossip.

use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, U256};
use parking_lot::Mutex;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

/// EIP-7825 per-transaction gas cap.
pub const TX_GAS_LIMIT_CAP: u64 = 1 << 24;

/// Largest accepted encoded transaction.
pub const MAX_TX_BYTES: usize = 128 * 1024;

/// Pool limits and chain rules.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Chain id transactions must be signed for.
    pub chain_id: u64,
    /// Block gas limit.
    pub block_gas_limit: u64,
    /// Minimum base fee (fee cap floor).
    pub min_base_fee: u64,
    /// Maximum number of transactions.
    pub max_txs: usize,
    /// Maximum total encoded size.
    pub max_bytes: usize,
    /// Maximum transactions per sender.
    pub max_per_sender: usize,
    /// Required tip increase to replace a transaction, in percent.
    pub price_bump_pct: u128,
    /// Transactions not included within this time are dropped.
    pub max_age: Duration,
}

impl PoolConfig {
    /// Defaults from the development plan.
    pub fn new(chain_id: u64, block_gas_limit: u64, min_base_fee: u64) -> Self {
        Self {
            chain_id,
            block_gas_limit,
            min_base_fee,
            max_txs: 4096,
            max_bytes: 16 << 20,
            max_per_sender: 16,
            price_bump_pct: 10,
            max_age: Duration::from_secs(3 * 3600),
        }
    }
}

/// Why a transaction was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddError {
    /// Not a valid EIP-2718 transaction.
    #[error("invalid transaction encoding")]
    Decode,
    /// Transaction is larger than [`MAX_TX_BYTES`].
    #[error("transaction too large")]
    TooLarge,
    /// Signature does not recover.
    #[error("invalid signature")]
    Signature,
    /// Blob transactions are not supported.
    #[error("blob transactions are not supported on Boltchain")]
    Blob,
    /// Missing EIP-155 replay protection.
    #[error("transaction must be replay-protected (EIP-155)")]
    Unprotected,
    /// Wrong chain id.
    #[error("wrong chain id {0}")]
    ChainId(u64),
    /// Gas limit exceeds the per-tx cap or block gas limit, or is below intrinsic 21000.
    #[error("gas limit {0} out of range")]
    GasLimit(u64),
    /// Gas limit below what the transaction must pay before executing: intrinsic gas (calldata,
    /// access list, authorizations, contract creation) or the EIP-7623 calldata floor.
    #[error("intrinsic gas too low: needs at least {0}")]
    IntrinsicGas(u64),
    /// Fee cap below the minimum base fee, or tip above fee cap.
    #[error("fee too low")]
    FeeTooLow,
    /// Nonce already used.
    #[error("nonce too low: next nonce is {0}")]
    NonceTooLow(u64),
    /// Nonce too far ahead.
    #[error("nonce too high")]
    NonceTooHigh,
    /// Balance does not cover gas * fee cap + value.
    #[error("insufficient funds for gas * price + value")]
    InsufficientFunds,
    /// Same nonce already pooled with a similar tip.
    #[error("replacement transaction underpriced")]
    Underpriced,
    /// Exact transaction already pooled.
    #[error("already known")]
    AlreadyKnown,
    /// Pool at capacity.
    #[error("transaction pool is full")]
    PoolFull,
}

/// A transaction in the pool.
#[derive(Debug, Clone)]
pub struct PooledTx {
    /// The transaction.
    pub tx: TxEnvelope,
    /// Recovered sender.
    pub sender: Address,
    /// Hash.
    pub hash: B256,
    /// Encoded size.
    pub size: usize,
    /// When the pool admitted it.
    pub admitted: Instant,
}

impl PooledTx {
    fn nonce(&self) -> u64 {
        self.tx.nonce()
    }
    fn tip(&self, base_fee: u64) -> Option<u128> {
        self.tx.effective_tip_per_gas(base_fee)
    }
    fn max_cost(&self) -> U256 {
        U256::from(self.tx.gas_limit()) * U256::from(self.tx.max_fee_per_gas()) + self.tx.value()
    }
}

/// Account state the pool validates against.
pub trait AccountState {
    /// (nonce, balance) of `addr` at the head.
    fn nonce_balance(&self, addr: &Address) -> (u64, U256);
}

#[derive(Debug, Default)]
struct Inner {
    by_hash: HashMap<B256, Arc<PooledTx>>,
    by_sender: HashMap<Address, BTreeMap<u64, B256>>,
    bytes: usize,
}

/// The transaction pool.
pub struct TxPool {
    cfg: PoolConfig,
    inner: Mutex<Inner>,
    /// Called with the raw bytes of every transaction admitted locally (RPC, forwarding), so the
    /// node can gossip it. Not called for transactions that arrived by gossip.
    on_admit: Mutex<Option<AdmitHook>>,
}

/// See [`TxPool::on_admit`].
pub type AdmitHook = Box<dyn Fn(&[u8]) + Send + Sync>;

impl std::fmt::Debug for TxPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxPool").field("len", &self.len()).finish()
    }
}

impl TxPool {
    /// Empty pool.
    pub fn new(cfg: PoolConfig) -> Self {
        Self { cfg, inner: Mutex::new(Inner::default()), on_admit: Mutex::new(None) }
    }

    /// Registers the hook called for every locally admitted transaction (see the field docs).
    pub fn on_admit(&self, hook: AdmitHook) {
        *self.on_admit.lock() = Some(hook);
    }

    /// Admits a raw transaction received from a peer by gossip (the hook is not called: gossip
    /// already relays it).
    pub fn add_gossiped(&self, raw: &[u8], state: &impl AccountState) -> Result<B256, AddError> {
        self.add_raw_inner(raw, state)
    }

    /// Decodes and admits a raw EIP-2718 transaction, then passes it to the admit hook.
    pub fn add_raw(&self, raw: &[u8], state: &impl AccountState) -> Result<B256, AddError> {
        let h = self.add_raw_inner(raw, state)?;
        if let Some(hook) = self.on_admit.lock().as_ref() {
            hook(raw);
        }
        Ok(h)
    }

    fn add_raw_inner(&self, raw: &[u8], state: &impl AccountState) -> Result<B256, AddError> {
        if raw.len() > MAX_TX_BYTES {
            return Err(AddError::TooLarge);
        }
        let mut buf = raw;
        let tx = TxEnvelope::decode_2718(&mut buf).map_err(|_| AddError::Decode)?;
        if !buf.is_empty() {
            return Err(AddError::Decode);
        }
        self.add(tx, state)
    }

    /// Admits a transaction.
    pub fn add(&self, tx: TxEnvelope, state: &impl AccountState) -> Result<B256, AddError> {
        let c = &self.cfg;
        if tx.is_eip4844() {
            return Err(AddError::Blob);
        }
        match tx.chain_id() {
            None => return Err(AddError::Unprotected),
            Some(id) if id != c.chain_id => return Err(AddError::ChainId(id)),
            _ => {}
        }
        let gas = tx.gas_limit();
        if !(21_000..=TX_GAS_LIMIT_CAP.min(c.block_gas_limit)).contains(&gas) {
            return Err(AddError::GasLimit(gas));
        }
        let needed = intrinsic_gas(&tx);
        if gas < needed {
            return Err(AddError::IntrinsicGas(needed));
        }
        if tx.max_fee_per_gas() < u128::from(c.min_base_fee)
            || tx.max_priority_fee_per_gas().is_some_and(|p| p > tx.max_fee_per_gas())
        {
            return Err(AddError::FeeTooLow);
        }
        let sender = tx.recover_signer().map_err(|_| AddError::Signature)?;
        let hash = *tx.tx_hash();
        let size = tx.encode_2718_len();
        let (account_nonce, balance) = state.nonce_balance(&sender);
        let nonce = tx.nonce();
        if nonce < account_nonce {
            return Err(AddError::NonceTooLow(account_nonce));
        }
        if nonce >= account_nonce + c.max_per_sender as u64 {
            return Err(AddError::NonceTooHigh);
        }
        let cost = U256::from(gas) * U256::from(tx.max_fee_per_gas()) + tx.value();
        if cost > balance {
            return Err(AddError::InsufficientFunds);
        }

        let mut inner = self.inner.lock();
        if inner.by_hash.contains_key(&hash) {
            return Err(AddError::AlreadyKnown);
        }
        let existing = inner.by_sender.get(&sender).and_then(|m| m.get(&nonce)).copied();
        if let Some(old_hash) = existing {
            let old = &inner.by_hash[&old_hash];
            let bump = |x: u128| x + x * c.price_bump_pct / 100;
            let old_tip = old.tx.max_priority_fee_per_gas().unwrap_or(old.tx.max_fee_per_gas());
            let new_tip = tx.max_priority_fee_per_gas().unwrap_or(tx.max_fee_per_gas());
            if new_tip < bump(old_tip) || tx.max_fee_per_gas() < bump(old.tx.max_fee_per_gas()) {
                return Err(AddError::Underpriced);
            }
            inner.remove(&old_hash);
        } else if inner.by_hash.len() >= c.max_txs || inner.bytes + size > c.max_bytes {
            return Err(AddError::PoolFull);
        }
        inner.bytes += size;
        inner.by_sender.entry(sender).or_default().insert(nonce, hash);
        inner
            .by_hash
            .insert(hash, Arc::new(PooledTx { tx, sender, hash, size, admitted: Instant::now() }));
        bolt_primitives::metrics::TXS_ADMITTED.inc();
        Ok(hash)
    }

    /// Executable transactions ordered for block building: per sender in nonce order starting
    /// at the account nonce, across senders by effective tip at `base_fee`.
    pub fn best(&self, base_fee: u64, state: &impl AccountState) -> Vec<(TxEnvelope, Address)> {
        let inner = self.inner.lock();
        // Per sender: the executable run of consecutive nonces.
        let mut runs: Vec<Vec<Arc<PooledTx>>> = Vec::new();
        for (sender, nonces) in &inner.by_sender {
            let start = state.nonce_balance(sender).0;
            let mut run = Vec::new();
            for (expected, (n, h)) in (start..).zip(nonces.range(start..)) {
                if *n != expected {
                    break; // nonce gap
                }
                let p = &inner.by_hash[h];
                if p.tip(base_fee).is_none() {
                    break; // fee cap below base fee: this and later nonces must wait
                }
                run.push(p.clone());
            }
            if !run.is_empty() {
                runs.push(run);
            }
        }
        // Merge runs by tip of their next transaction.
        let mut heap: BinaryHeap<(u128, Reverse<usize>, usize)> = BinaryHeap::new();
        for (i, run) in runs.iter().enumerate() {
            heap.push((run[0].tip(base_fee).unwrap_or(0), Reverse(i), 0));
        }
        let mut out = Vec::new();
        while let Some((_, Reverse(i), j)) = heap.pop() {
            let p = &runs[i][j];
            out.push((p.tx.clone(), p.sender));
            if let Some(next) = runs[i].get(j + 1) {
                heap.push((next.tip(base_fee).unwrap_or(0), Reverse(i), j + 1));
            }
        }
        out
    }

    /// Drops transactions that are now included, expired, or no longer affordable (see the
    /// module docs).
    pub fn on_new_block(&self, state: &impl AccountState) {
        self.evict(state, Instant::now());
    }

    fn evict(&self, state: &impl AccountState, now: Instant) {
        let mut inner = self.inner.lock();
        let senders: Vec<Address> = inner.by_sender.keys().copied().collect();
        for s in senders {
            let (nonce, balance) = state.nonce_balance(&s);
            let mut drop: Vec<B256> = Vec::new();
            for (n, h) in &inner.by_sender[&s] {
                let p = &inner.by_hash[h];
                let expired = now.saturating_duration_since(p.admitted) > self.cfg.max_age;
                // the next one to execute: it can only run if the balance still covers it
                let unaffordable = *n == nonce && p.max_cost() > balance;
                if *n < nonce || expired || unaffordable {
                    drop.push(*h);
                }
            }
            for h in drop {
                inner.remove(&h);
            }
        }
    }

    /// Removes transactions by hash (e.g. ones a block builder found invalid).
    pub fn remove(&self, hashes: &[B256]) {
        let mut inner = self.inner.lock();
        for h in hashes {
            inner.remove(h);
        }
    }

    /// Next nonce for `sender` counting pooled transactions ("pending" block tag).
    pub fn pending_nonce(&self, sender: &Address, account_nonce: u64) -> u64 {
        let inner = self.inner.lock();
        let mut next = account_nonce;
        if let Some(m) = inner.by_sender.get(sender) {
            while m.contains_key(&next) {
                next += 1;
            }
        }
        next
    }

    /// A pooled transaction by hash.
    pub fn get(&self, hash: &B256) -> Option<Arc<PooledTx>> {
        self.inner.lock().by_hash.get(hash).cloned()
    }

    /// Number of pooled transactions.
    pub fn len(&self) -> usize {
        self.inner.lock().by_hash.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Inner {
    fn remove(&mut self, hash: &B256) {
        if let Some(p) = self.by_hash.remove(hash) {
            self.bytes -= p.size;
            if let Some(m) = self.by_sender.get_mut(&p.sender) {
                m.remove(&p.nonce());
                if m.is_empty() {
                    self.by_sender.remove(&p.sender);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

/// Gas a transaction must provide before any execution under the chain's rules (Osaka): the
/// intrinsic cost or the EIP-7623 calldata floor, whichever is higher. Execution rejects a
/// transaction below it, so the pool must too (otherwise it would be accepted and silently
/// dropped at block building).
pub fn intrinsic_gas(tx: &TxEnvelope) -> u64 {
    use alloy_consensus::Transaction as _;
    let (accounts, storages) = tx.access_list().map_or((0, 0), |al| {
        (al.len() as u64, al.iter().map(|i| i.storage_keys.len() as u64).sum())
    });
    let auths = tx.authorization_list().map_or(0, |a| a.len() as u64);
    let g = revm::context_interface::cfg::gas::calculate_initial_tx_gas(
        revm::primitives::hardfork::SpecId::OSAKA,
        tx.input(),
        tx.kind().is_create(),
        accounts,
        storages,
        auths,
        None,
    );
    (g.initial_regular_gas + g.initial_state_gas).max(g.floor_gas)
}
