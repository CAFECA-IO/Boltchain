//! Boltchain node binary.

use boltchain::{bench, compute, devnet, follow, keys, swarm, validator, wallet};

use anyhow::{Context, Result};
use bolt_primitives::Genesis;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "boltchain", version = boltchain::VERSION, about = "Boltchain node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Genesis file tools.
    #[command(subcommand)]
    Genesis(GenesisCmd),
    /// Print the protocol constants this binary was built with.
    Params,
    /// Validator key tools.
    #[command(subcommand)]
    Keys(keys::KeysCmd),
    /// Account wallet: create a key, check balances, send BOLT, stake, publish a history peer.
    #[command(subcommand)]
    Wallet(wallet::WalletCmd),
    /// SwarmStorage (ADR 0014): store encrypted files with paid providers, offer storage.
    #[command(subcommand)]
    Storage(swarm::StorageCmd),
    /// AI compute market (ADR 0011), provider side: register, serve jobs with an
    /// OpenAI-compatible backend (llama.cpp, Ollama, vLLM), collect earnings.
    #[command(subcommand)]
    Provider(compute::ProviderCmd),
    /// AI compute market, requester side: post a prompt, read the result, approve or dispute.
    #[command(subcommand)]
    Job(compute::JobCmd),
    /// AI model registry (ADR 0011): register a model by its weights CID, list models, declare
    /// which ones a provider serves.
    #[command(subcommand)]
    Model(compute::ModelCmd),
    /// Verifier program for `--verifier-cmd`: re-runs a disputed compute job on an
    /// OpenAI-compatible backend and prints `fault`, `ok` or `abstain` (job from `BOLT_*`).
    Judge(compute::JudgeArgs),
    /// Run a single-producer development network with JSON-RPC, announcing blocks over IPFS.
    Devnet(devnet::DevnetArgs),
    /// Follow a producer: sync blocks over IPFS, serve JSON-RPC, forward transactions.
    Follow(follow::FollowArgs),
    /// Run a validator: take part in consensus, produce and finalize blocks.
    Validator(validator::ValidatorArgs),
    /// Mine: follow the chain and seal blocks with RandomBOLT until PoS starts, then keep
    /// following it (same as `validator --mine` without keys).
    Mine(validator::ValidatorArgs),
    /// Print the peer id of a node key (creating the key if missing).
    NodeId {
        /// Node key file.
        #[arg(long)]
        node_key: PathBuf,
    },
    /// Benchmark block execution (transfers and the worst-case pairing block).
    Bench(bench::BenchArgs),
    /// History tools.
    #[command(subcommand)]
    History(HistoryCmd),
}

#[derive(Debug, Subcommand)]
enum HistoryCmd {
    /// Export one epoch's blocks (index, envelopes, headers, bodies) as a CAR file, e.g. for
    /// `ipfs dag import` or long-term archiving.
    Export {
        /// Genesis file.
        #[arg(long, default_value = "genesis/dev.json")]
        genesis: PathBuf,
        /// Data directory (the node must be stopped).
        #[arg(long)]
        datadir: PathBuf,
        /// Epoch.
        #[arg(long)]
        epoch: u64,
        /// Output file.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum GenesisCmd {
    /// Validate a genesis file and print its block hash and state root.
    Inspect {
        /// Path to genesis.json.
        path: PathBuf,
    },
    /// Write a dev-chain genesis. With validators (insecure deterministic dev keys, staked at
    /// genesis) the chain runs PoS from block 1; with `--validators 0` it starts mined.
    MakeDev {
        /// Output file.
        #[arg(long)]
        out: PathBuf,
        /// Chain id (8017 produces a mainnet-shaped test genesis: no validators, no funds).
        #[arg(long, default_value_t = 1337)]
        chain_id: u64,
        /// Number of genesis validators (dev chains only).
        #[arg(long, default_value_t = 7)]
        validators: u32,
        /// Accounts to fund with 10,000 BOLT each (dev chains only).
        #[arg(long)]
        fund: Vec<alloy_primitives::Address>,
        /// Header extra data.
        #[arg(long, default_value = "Boltchain dev")]
        extra: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,libmdbx=warn".into()),
        )
        // Colours only on a terminal: log files and journald get plain text.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    boltchain::raise_open_file_limit();
    match Cli::parse().command {
        Command::Devnet(args) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(devnet::run(args))?;
        }
        Command::Bench(args) => bench::run(args)?,
        Command::Keys(cmd) => keys::run(cmd)?,
        Command::Wallet(cmd) => wallet::run(cmd)?,
        Command::Storage(cmd) => swarm::run(cmd)?,
        Command::Provider(cmd) => compute::run_provider(cmd)?,
        Command::Job(cmd) => compute::run_job(cmd)?,
        Command::Model(cmd) => compute::run_model(cmd)?,
        Command::Judge(args) => {
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            match compute::judge(&args, &env) {
                Ok((verdict, notes)) => {
                    println!("{verdict}");
                    for n in notes {
                        println!("{n}");
                    }
                }
                Err(e) => println!("abstain\n{e:#}"),
            }
        }
        Command::Follow(args) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(follow::run(args))?;
        }
        Command::Mine(mut args) => {
            args.mining.mine = true;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(validator::run(args))?;
        }
        Command::Validator(args) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(validator::run(args))?;
        }
        Command::History(HistoryCmd::Export { genesis, datadir, epoch, out }) => {
            let genesis = devnet::load_genesis(&genesis)?;
            let chain = bolt_chain::Chain::open(&datadir, &genesis)?;
            let car = boltchain::gateway::export_epoch(&chain, epoch)?;
            std::fs::write(&out, &car)?;
            println!("wrote epoch {epoch} ({} bytes) to {}", car.len(), out.display());
        }
        Command::NodeId { node_key } => {
            let key = bolt_net::load_or_create_key(&node_key)?;
            println!("{}", key.public().to_peer_id());
        }
        Command::Genesis(GenesisCmd::MakeDev { out, chain_id, validators, fund, extra }) => {
            let g = make_dev_genesis(chain_id, validators, &fund, &extra)?;
            std::fs::write(&out, serde_json::to_string_pretty(&g)? + "\n")?;
            println!("wrote {} (genesis hash {})", out.display(), bolt_system::genesis_hash(&g)?);
        }
        Command::Genesis(GenesisCmd::Inspect { path }) => {
            let json = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let genesis = Genesis::from_json(&json)?;
            let header = bolt_system::genesis_header(&genesis)?;
            println!("genesis valid");
            println!("  chain id          {}", genesis.config.chain_id);
            println!("  block hash        {}", header.hash_slow());
            println!("  state root        {}", header.state_root);
            println!("  initial seed      {}", header.mix_hash);
            if genesis.starts_with_pow() {
                let p = &genesis.config.pow;
                let (stakers, stake, streak) = genesis.config.pos_thresholds();
                println!(
                    "  starts            mined ({:?}, difficulty {}, {}s blocks)",
                    p.algorithm, p.initial_difficulty, p.block_seconds
                );
                let (cp_stakers, cp_stake) = genesis.config.checkpoint_thresholds();
                println!(
                    "  checkpoints when  {cp_stakers} stakers and {cp_stake} BOLT staked for {streak} epochs (depth {})",
                    genesis.config.checkpoint_depth()
                );
                println!(
                    "  PoS when          {stakers} stakers and {stake} BOLT staked for {streak} epochs"
                );
            } else {
                println!(
                    "  starts            PoS ({} genesis validators)",
                    genesis.dev_validators.len()
                );
            }
            println!("  governance        none (rules change by hard fork only)");
        }
        Command::Params => {
            use bolt_primitives::params::*;
            println!("evm spec          {:?}", bolt_exec::SPEC);
            println!("chain id          {CHAIN_ID}");
            println!("slot              {SLOT_SECONDS}s, epoch {EPOCH_SLOTS} slots");
            println!("committee floor   {MIN_COMMITTEE_SIZE}");
            println!("gas limit         {DEFAULT_GAS_LIMIT} (range {GAS_LIMIT_RANGE:?})");
            println!("supply cap        none");
            println!("min stake         {} BOLT", MIN_STAKE_WEI / WEI_PER_BOLT);
            println!(
                "emission          per block: consensus 31/15/7/3 then {TAIL_CONSENSUS_REWARD_BOLT} BOLT (halving every {} days), storage {STORAGE_BLOCK_REWARD_BOLT} BOLT",
                HALVING_SECONDS / 86_400
            );
            println!(
                "mining            RandomBOLT, {POW_BLOCK_SECONDS}s blocks, ASERT half-life {POW_HALF_LIFE_SECONDS}s, reorgs <= {MAX_REORG_DEPTH}"
            );
            println!(
                "checkpoints       {CHECKPOINT_MIN_STAKERS} stakers, {CHECKPOINT_MIN_TOTAL_STAKE_BOLT} BOLT, held {POS_STREAK_EPOCHS} epochs; depth {CHECKPOINT_DEPTH}; miners {}%",
                CHECKPOINT_MINER_BPS / 100
            );
            println!(
                "PoS starts        {POS_MIN_STAKERS} stakers, {POS_MIN_TOTAL_STAKE_BOLT} BOLT, held {POS_STREAK_EPOCHS} epochs"
            );
        }
    }
    Ok(())
}

/// Dev genesis with deterministic validator keys staked at genesis (PoS from block 1), or a
/// mined start without validators.
fn make_dev_genesis(
    chain_id: u64,
    validators: u32,
    fund: &[alloy_primitives::Address],
    extra: &str,
) -> Result<Genesis> {
    use bolt_primitives::{bls, genesis::*, params::*};
    let dev = chain_id != CHAIN_ID;
    if !dev && (!fund.is_empty() || validators > 0) {
        anyhow::bail!("chain id {CHAIN_ID} genesis cannot fund accounts or list validators");
    }
    let dev_validators = (0..validators)
        .map(|i| {
            let k = bls::dev_key(i);
            let sk = k256::ecdsa::SigningKey::from_slice(&bls::dev_eth_key(i)).expect("valid key");
            let addr = alloy_primitives::Address::from_public_key(sk.verifying_key());
            DevValidator {
                name: format!("dev-{i}"),
                bls_pubkey: k.public_key(),
                proof_of_possession: k.proof_of_possession(),
                owner: addr,
                fee_recipient: addr,
                stake_bolt: 1_000,
            }
        })
        .collect();
    let alloc = fund
        .iter()
        .map(|a| {
            (
                *a,
                GenesisAccount {
                    balance: alloy_primitives::U256::from(10_000u128 * WEI_PER_BOLT),
                    ..Default::default()
                },
            )
        })
        .collect();
    let g = Genesis {
        dev,
        config: ChainConfig { chain_id, ..ChainConfig::default() },
        timestamp: 0,
        extra_data: extra.as_bytes().to_vec().into(),
        dev_validators,
        alloc,
    };
    g.validate()?;
    Ok(g)
}
