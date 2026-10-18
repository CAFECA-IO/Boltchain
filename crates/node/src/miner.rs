//! Miner: seals blocks with RandomBOLT on the local head until PoS starts (ADR 0007 §1).
//!
//! Each round builds a template from the pool on the current head, then searches nonces on
//! `threads` blocking workers. The search restarts when the head changes (a block arrived) or
//! the template is older than one block interval (fresher transactions and timestamp).

use alloy_primitives::{Address, Bytes};
use anyhow::Result;
use bolt_chain::{Chain, ChainError, pow::MinedOutcome};
use bolt_net::NetHandle;
use bolt_pow::{Mode, Pow};
use bolt_rpc::HeadState;
use bolt_txpool::TxPool;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Miner options.
#[derive(Debug, Clone)]
pub struct MinerConfig {
    /// Receives block rewards and tips.
    pub beneficiary: Address,
    /// Search threads.
    pub threads: usize,
    /// RandomX mode (fast: 2 GiB dataset, much faster hashing).
    pub mode: Mode,
    /// Header extra data (at most 32 bytes).
    pub extra_data: Bytes,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Latest checkpoint QC known to this node (epoch, encoded certificate), put into mined blocks in
/// phase B so its signers get paid.
pub type CertSlot = Arc<parking_lot::Mutex<Option<(u64, Vec<u8>)>>>;

/// Mines until PoS starts or the task is aborted. Publishes every block it finds.
pub async fn run(
    chain: Arc<Chain>,
    pool: Arc<TxPool>,
    net: NetHandle,
    cfg: MinerConfig,
    cert: CertSlot,
) -> Result<()> {
    let pow = Pow::with_mode(chain.pow().algorithm(), cfg.mode);
    let threads = cfg.threads.max(1);
    let spacing = chain.config().pow.block_seconds.max(1);
    let mut round: u64 = 0;
    loop {
        round += 1;
        let head = chain.head()?;
        let parent = head.hash_slow();
        let candidates = {
            let r = chain.store().reader()?;
            pool.best(chain.next_base_fee()?, &HeadState(&r))
        };
        let (c, beneficiary, extra) = (chain.clone(), cfg.beneficiary, cfg.extra_data.clone());
        let timestamp = now_secs().max(head.timestamp + 1);
        // Phase B: carry the latest checkpoint QC of this block's epoch (it pays the signers).
        let number = head.number + 1;
        let block_cert = match cert.lock().clone() {
            Some((epoch, bytes))
                if epoch == chain.rules().epoch_of(number)
                    && chain.phase()?.is_checkpointing(chain.rules(), number) =>
            {
                bytes
            }
            _ => Vec::new(),
        };
        let template = match tokio::task::spawn_blocking(move || {
            c.build_template(candidates, timestamp, beneficiary, extra, block_cert)
        })
        .await?
        {
            Ok(t) => t,
            Err(ChainError::InvalidBlock(e))
                if chain.phase()?.is_pos(chain.rules(), head.number + 1) =>
            {
                tracing::info!("PoS has started; mining stops ({e})");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!("cannot build a block template: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        // transactions that can never execute leave the pool (see validator::propose)
        let invalid: Vec<_> = template.rejected.iter().filter(|r| r.2).map(|r| r.0).collect();
        if !invalid.is_empty() {
            pool.remove(&invalid);
        }
        let key = chain.seal_key(&parent, head.number + 1)?;
        let seal = bolt_pow::seal_hash(&template.header);
        let difficulty = template.header.difficulty;
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(threads);
        let started = Instant::now();
        let base = round.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (now_secs() << 20);
        for t in 0..threads as u64 {
            let (pow, stop, tx, chain) = (pow.clone(), stop.clone(), tx.clone(), chain.clone());
            tokio::task::spawn_blocking(move || {
                let mut start = base.wrapping_add(t);
                let mut checked = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    match pow.search(&key, &seal, difficulty, start, threads as u64, 64, &stop) {
                        Ok(Some((nonce, _))) => {
                            stop.store(true, Ordering::Relaxed);
                            let _ = tx.blocking_send(nonce);
                            return;
                        }
                        Ok(None) => {
                            bolt_primitives::metrics::HASHES.add(64);
                            start = start.wrapping_add(64 * threads as u64)
                        }
                        Err(e) => {
                            tracing::error!("hashing failed: {e}");
                            stop.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                    if checked.elapsed() < Duration::from_millis(100) {
                        continue;
                    }
                    checked = Instant::now();
                    let stale = chain.head().map(|h| h.hash_slow() != parent).unwrap_or(true)
                        || started.elapsed() > Duration::from_secs(spacing);
                    if stale {
                        stop.store(true, Ordering::Relaxed);
                    }
                }
            });
        }
        drop(tx);
        let Some(nonce) = rx.recv().await else {
            // Stale template (new head or timeout): start over.
            chain.drop_pending(&template.hash);
            continue;
        };
        let c = chain.clone();
        let t = template.clone();
        match tokio::task::spawn_blocking(move || c.seal_and_import(&t, nonce)).await? {
            Ok((header, outcome)) => {
                let number = header.number;
                if outcome == MinedOutcome::Extended
                    || matches!(outcome, MinedOutcome::Reorged { .. })
                {
                    bolt_primitives::metrics::BLOCKS_MINED.inc();
                    tracing::info!(
                        number,
                        hash = %header.hash_slow(),
                        difficulty = %header.difficulty,
                        txs = template.included.len(),
                        "mined block"
                    );
                    if let Ok(r) = chain.store().reader() {
                        pool.on_new_block(&HeadState(&r));
                    }
                    if let Some(a) = bolt_sync::announce_stored(&chain, number, Vec::new()) {
                        let _ = net.publish(a).await;
                    }
                }
            }
            // The template's parent was reorganised away while the nonce was being found.
            Err(bolt_chain::ChainError::UnknownParent(p)) => {
                tracing::debug!(parent = %p, "sealed block is stale (parent reorganised away)")
            }
            Err(e) => tracing::warn!("sealed block not imported: {e}"),
        }
    }
}

/// Mining options (CLI).
#[derive(Debug, Clone, clap::Args)]
pub struct MiningArgs {
    /// Mine while the chain is in its mining phase (before PoS starts).
    #[arg(long)]
    pub mine: bool,
    /// Address that receives mining rewards (required with --mine).
    #[arg(long)]
    pub beneficiary: Option<Address>,
    /// Mining threads.
    #[arg(long, default_value_t = 1)]
    pub mining_threads: usize,
    /// Use RandomX fast mode (2 GiB dataset per key; much faster hashing).
    #[arg(long)]
    pub randomx_fast: bool,
    /// Extra data in mined blocks (at most 32 bytes).
    #[arg(long, default_value = "")]
    pub extra_data: String,
    /// Gas limit this node's blocks vote for (each block moves it by less than 1/1024).
    #[arg(long)]
    pub gas_target: Option<u64>,
}

impl MiningArgs {
    /// The miner configuration, if mining.
    pub fn config(&self) -> Result<Option<MinerConfig>> {
        if !self.mine {
            return Ok(None);
        }
        let beneficiary =
            self.beneficiary.ok_or_else(|| anyhow::anyhow!("--mine needs --beneficiary"))?;
        anyhow::ensure!(self.extra_data.len() <= 32, "--extra-data is limited to 32 bytes");
        Ok(Some(MinerConfig {
            beneficiary,
            threads: self.mining_threads,
            mode: if self.randomx_fast { Mode::Fast } else { Mode::Light },
            extra_data: self.extra_data.as_bytes().to_vec().into(),
        }))
    }
}
