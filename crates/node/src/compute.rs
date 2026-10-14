//! `boltchain provider` and `boltchain job`: the AI compute market from the command line
//! (ADR 0011).
//!
//! Files are bolt-vault envelopes on IPFS, handed to and fetched from the user's own node through
//! `bolt_hostBlocks` / `bolt_getBlocks` (the node runs with `--rpc-storage`). Every account's
//! vault key is derived from its account key (the same key `boltchain storage` uses), and a
//! provider registers its public half in `ComputeMarket` so requesters can encrypt for it.
//!
//! - Input (requester → provider): JSON `{"messages": [...], "max_tokens": n}`, the body of an
//!   OpenAI-compatible chat completion request without the model name.
//! - Output (provider → requester): the backend's JSON response (`choices`, `usage`, …).
//!
//! The provider serves jobs with any OpenAI-compatible HTTP backend (llama.cpp's
//! `llama-server`, Ollama, vLLM): `--backend http://127.0.0.1:8080` and
//! `--model <id>=<backend model name>` for each `ModelRegistry` id it runs. Token counts come
//! from the backend's `usage` and are capped at the job's maxima. It asks the backend for the
//! top-k log-probabilities of every output token and delivers them with the answer, so a
//! verifier panel can compare its own re-run token by token (`boltchain judge`).
//!
//! Jobs are either addressed to one provider (the input is encrypted for it at once) or open to
//! any provider (`job post` without `--provider`): a provider running with `--open` takes it,
//! then the requester's `job watch` (or `post --wait`) adds the provider as a recipient of the
//! input (`shareInput`, no re-upload).
//!
//! A provider without BOLT signs its actions and hands them to a relay (`--relay <URL>`, a node
//! started with `--relay-wallet`), which pays the gas and is paid a fee from the job.

use crate::{
    swarm::vault_key,
    wallet::{format_bolt, load_wallet, parse_bolt, rpc, send_tx},
};
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, Result, bail};
use bolt_ipld::Cid;
use bolt_system::{
    abi::{IComputeMarket, IModelRegistry},
    addresses::{COMPUTE, MODELS},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

const RPC: &str = "http://127.0.0.1:8545";

/// Job states in `ComputeMarket`.
pub mod state {
    /// Posted, waiting for its provider.
    pub const OPEN: u8 = 1;
    /// Taken by the provider.
    pub const ACCEPTED: u8 = 2;
    /// Result delivered, dispute window running.
    pub const DELIVERED: u8 = 3;
    /// Disputed, waiting for the verifier panel.
    pub const DISPUTED: u8 = 4;
    /// Paid.
    pub const SETTLED: u8 = 5;
    /// Escrow returned.
    pub const REFUNDED: u8 = 6;
}

fn state_name(s: u8) -> &'static str {
    match s {
        state::OPEN => "open",
        state::ACCEPTED => "accepted",
        state::DELIVERED => "delivered",
        state::DISPUTED => "disputed",
        state::SETTLED => "settled",
        state::REFUNDED => "refunded",
        _ => "none",
    }
}

/// Provider commands.
#[derive(Debug, clap::Subcommand)]
pub enum ProviderCmd {
    /// Register this account as a compute provider (publishes its encryption key). Needs a
    /// little BOLT for gas.
    Register {
        /// Account key file (receives the earnings).
        #[arg(long)]
        wallet: PathBuf,
        /// The node's identity key (`<datadir>/node.key`), published as the provider's peer.
        #[arg(long)]
        node_key: PathBuf,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
        #[command(flatten)]
        relay: RelayArgs,
    },
    /// Serve jobs addressed to this account with an OpenAI-compatible backend until stopped.
    Run {
        /// Account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// Backend base URL (http only), e.g. llama-server on `http://127.0.0.1:8080`.
        #[arg(long)]
        backend: String,
        /// Model a job id maps to on the backend: `<id>=<name>` (repeatable), e.g. `1=qwen2.5-7b`.
        #[arg(long = "model", value_name = "ID=NAME", required = true)]
        models: Vec<String>,
        /// JSON-RPC endpoint of your node (started with `--rpc-storage`).
        #[arg(long, default_value = RPC)]
        rpc: String,
        /// Seconds between scans for new jobs.
        #[arg(long, default_value_t = 5)]
        interval: u64,
        /// Also take jobs open to any provider (for a model in `--model`) paying at least
        /// `--min-price-in` / `--min-price-out`.
        #[arg(long)]
        open: bool,
        /// Smallest price, in BOLT per 1,000 input tokens, of an open job to take.
        #[arg(long, default_value = "0")]
        min_price_in: String,
        /// Smallest price, in BOLT per 1,000 output tokens, of an open job to take.
        #[arg(long, default_value = "0")]
        min_price_out: String,
        /// Top log-probabilities requested per output token and delivered with the answer
        /// (lets verifiers compare token by token; 0 turns it off).
        #[arg(long, default_value_t = 5)]
        top_logprobs: u32,
        #[command(flatten)]
        relay: RelayArgs,
    },
    /// Show a provider's registration, bond, jobs and balance.
    Status {
        /// Provider address.
        address: Address,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Settle this provider's delivered jobs whose dispute window has passed, then withdraw.
    Collect {
        /// Account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
        #[command(flatten)]
        relay: RelayArgs,
    },
}

/// Sending a provider's actions through a relay instead of paying gas.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RelayArgs {
    /// JSON-RPC URL of a relaying node (`--relay-wallet`): your actions are signed here and
    /// submitted by it, so this account needs no BOLT.
    #[arg(long, value_name = "URL")]
    pub relay: Option<String>,
    /// Fee, in BOLT, offered to the relay per action (paid from the job when it settles; a
    /// registration fee is repaid from the first earnings).
    #[arg(long, default_value = "0.001")]
    pub relay_fee: String,
}

impl RelayArgs {
    /// `(relay URL, fee in wei)` when a relay is set.
    pub fn resolve(&self) -> Result<Option<(String, U256)>> {
        Ok(match &self.relay {
            Some(u) => Some((u.clone(), parse_bolt(&self.relay_fee)?)),
            None => None,
        })
    }
}

/// Requester commands.
#[derive(Debug, clap::Subcommand)]
pub enum JobCmd {
    /// Encrypt a prompt for a provider, hand it to your node and escrow the maximum cost.
    Post {
        /// Account key file (pays).
        #[arg(long)]
        wallet: PathBuf,
        /// Provider address (must be registered). Without it the job is open to any provider.
        #[arg(long)]
        provider: Option<Address>,
        /// Model id in `ModelRegistry` (`boltchain model list`).
        #[arg(long)]
        model: u64,
        /// Prompt text (a single user message).
        #[arg(long, conflicts_with = "input")]
        prompt: Option<String>,
        /// Request JSON file: `{"messages": [...]}` (OpenAI chat format, without `model`).
        #[arg(long)]
        input: Option<PathBuf>,
        /// Price in BOLT per 1,000 input tokens.
        #[arg(long)]
        price_in: String,
        /// Price in BOLT per 1,000 output tokens.
        #[arg(long)]
        price_out: String,
        /// Largest number of input tokens paid for.
        #[arg(long, default_value_t = 4096)]
        max_in: u64,
        /// Largest number of output tokens paid for (also sent as `max_tokens`).
        #[arg(long, default_value_t = 1024)]
        max_out: u64,
        /// Minutes the provider has to deliver.
        #[arg(long, default_value_t = 60)]
        deadline: u64,
        /// Minutes you have to dispute a delivery (10 to 10,080).
        #[arg(long, default_value_t = 30)]
        window: u64,
        /// Keep running: share the input with whoever takes an open job, then print the result.
        #[arg(long)]
        wait: bool,
        /// Require the answer's top log-probabilities per token (a delivery without them is at
        /// fault in a dispute).
        #[arg(long)]
        logprobs: bool,
        /// JSON-RPC endpoint of your node (started with `--rpc-storage`).
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Follow a job you posted: share its input with the provider that takes it (open jobs),
    /// then print the result when it is delivered.
    Watch {
        /// Account key file (the requester).
        #[arg(long)]
        wallet: PathBuf,
        /// Job id.
        id: u64,
        /// JSON-RPC endpoint of your node (started with `--rpc-storage`).
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Show a job.
    Status {
        /// Job id.
        id: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Fetch and decrypt a delivered result (prints the answer; `--out` saves the full JSON).
    Result {
        /// Account key file (the requester).
        #[arg(long)]
        wallet: PathBuf,
        /// Job id.
        id: u64,
        /// Save the backend's full response here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// JSON-RPC endpoint of your node (started with `--rpc-storage`).
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Accept a delivery and pay the provider now.
    Approve {
        /// Account key file (the requester).
        #[arg(long)]
        wallet: PathBuf,
        /// Job id.
        id: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Dispute a delivery within its window (1 BOLT deposit, returned if the provider is found
    /// at fault).
    Dispute {
        /// Account key file (the requester).
        #[arg(long)]
        wallet: PathBuf,
        /// Job id.
        id: u64,
        /// What is wrong with the result.
        #[arg(long)]
        reason: String,
        /// JSON-RPC endpoint of your node (started with `--rpc-storage`).
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// After a verifier panel is assigned to your dispute, re-encrypt the job's input, output and
    /// your reason for the panel members and send it to them (through your node).
    Share {
        /// Account key file (the requester).
        #[arg(long)]
        wallet: PathBuf,
        /// Job id.
        id: u64,
        /// JSON-RPC endpoint of your node (started with `--rpc-storage`).
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Get the escrow back from a job nobody delivered by its deadline.
    Refund {
        /// Account key file (the requester).
        #[arg(long)]
        wallet: PathBuf,
        /// Job id.
        id: u64,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Withdraw your ComputeMarket balance (refunds, returned deposits, earnings).
    Withdraw {
        /// Account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
}

// ---------------------------------------------------------------------------------------------
// Chain and node access.

/// `eth_call` to ComputeMarket.
pub fn call<C: SolCall>(url: &str, c: C) -> Result<C::Return> {
    let out = rpc(
        url,
        "eth_call",
        json!([{"to": COMPUTE, "data": hex::encode_prefixed(c.abi_encode())}, "latest"]),
    )?;
    let bytes: Bytes = serde_json::from_value(out)?;
    Ok(C::abi_decode_returns(&bytes)?)
}

fn chain_time(url: &str) -> Result<u64> {
    let b = rpc(url, "eth_getBlockByNumber", json!(["latest", false]))?;
    let t = b["timestamp"].as_str().context("block timestamp")?;
    Ok(u64::from_str_radix(t.trim_start_matches("0x"), 16)?)
}

fn to_ipld(c: &bolt_vault::Cid) -> Cid {
    Cid::try_from(c.to_bytes().as_slice()).expect("vault CIDs are raw sha2-256 CIDv1")
}

/// Seals `data` for `recipients` and hands every block to the node; returns the envelope CID.
pub fn seal_and_host(
    url: &str,
    data: &[u8],
    name: &str,
    recipients: &[bolt_vault::PublicKey],
) -> Result<Cid> {
    let sealed = bolt_vault::seal(data, name, "application/json", recipients, &Default::default())?;
    let root = to_ipld(&sealed.envelope.cid);
    let blocks: Vec<Value> = sealed
        .blocks()
        .map(|b| json!([to_ipld(&b.cid).to_string(), hex::encode_prefixed(&b.data)]))
        .collect();
    for chunk in blocks.chunks(64) {
        rpc(url, "bolt_hostBlocks", json!([root.to_string(), chunk]))?;
    }
    Ok(root)
}

/// Fetches (through the node) and decrypts the bolt-vault file named by envelope CID bytes.
pub fn fetch_and_open(url: &str, envelope: &[u8], sk: &bolt_vault::SecretKey) -> Result<Vec<u8>> {
    let root = Cid::try_from(envelope).context("envelope CID")?;
    let get = |cids: &[Cid]| -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for chunk in cids.chunks(64) {
            let names: Vec<String> = chunk.iter().map(|c| c.to_string()).collect();
            let v = rpc(url, "bolt_getBlocks", json!([names, null, root.to_string()]))?;
            let got: Vec<Bytes> = serde_json::from_value(v)?;
            out.extend(got.into_iter().map(|b| b.to_vec()));
        }
        Ok(out)
    };
    let env_block = get(&[root])?.remove(0);
    let env = bolt_vault::parse_envelope(&env_block)?;
    let key = bolt_vault::open_key(&env, sk)?;
    let mblock = get(&[to_ipld(&env.manifest)])?.remove(0);
    let manifest = bolt_vault::open_manifest(&env, &mblock, &key)?;
    let cids: Vec<Cid> = manifest.shards.iter().map(to_ipld).collect();
    let shards: Vec<Option<Vec<u8>>> = get(&cids)?.into_iter().map(Some).collect();
    Ok(bolt_vault::recover(&manifest, &key, &shards)?)
}

/// The account's registered encryption key.
fn encryption_key(url: &str, account: Address) -> Result<bolt_vault::PublicKey> {
    let k = call(url, IComputeMarket::encryptionKeyCall { account })?;
    if k == B256::ZERO {
        bail!("{account} has no encryption key in ComputeMarket (not a registered provider?)");
    }
    Ok(bolt_vault::PublicKey::from_bytes(k.as_slice())?)
}

/// POSTs JSON to an `http://` URL; returns the JSON response.
pub fn http_post_json(url: &str, body: &Value, timeout: Duration) -> Result<Value> {
    let rest = url.strip_prefix("http://").context("only http:// backends are supported")?;
    let (host, path) =
        rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let body = body.to_string();
    let mut s =
        std::net::TcpStream::connect(host).with_context(|| format!("connecting to {host}"))?;
    s.set_read_timeout(Some(timeout))?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp)?;
    let resp = String::from_utf8_lossy(&resp);
    let (head, json_body) = resp.split_once("\r\n\r\n").context("bad HTTP response")?;
    let status = head.split_whitespace().nth(1).unwrap_or("?");
    if !status.starts_with('2') {
        bail!(
            "backend answered HTTP {status}: {}",
            json_body.chars().take(300).collect::<String>()
        );
    }
    let start = json_body.find('{').context("no JSON in response")?;
    let end = json_body.rfind('}').context("no JSON in response")?;
    Ok(serde_json::from_str(&json_body[start..=end])?)
}

fn event_topic(sig: &str) -> B256 {
    keccak256(sig.as_bytes())
}

fn first_indexed(url: &str, hash: B256, sig: &str) -> Result<U256> {
    let topic = event_topic(sig);
    let r = rpc(url, "eth_getTransactionReceipt", json!([hash]))?;
    for log in r["logs"].as_array().into_iter().flatten() {
        let topics: Vec<B256> = serde_json::from_value(log["topics"].clone()).unwrap_or_default();
        if topics.first() == Some(&topic) && topics.len() > 1 {
            return Ok(U256::from_be_bytes(topics[1].0));
        }
    }
    bail!("no {sig} log in {hash}")
}

// ---------------------------------------------------------------------------------------------
// Provider.

/// Signs a `ComputeMarket` action (`register`, `accept`, `deliver`) for submission by others.
pub fn sign_action(
    url: &str,
    s: &PrivateKeySigner,
    action: &str,
    data: Vec<u8>,
    deadline: u64,
) -> Result<Bytes> {
    let digest = call(
        url,
        IComputeMarket::actionDigestCall {
            action: B256::right_padding_from(action.as_bytes()),
            signer: s.address(),
            data: data.into(),
            deadline: U256::from(deadline),
        },
    )?;
    let sig = alloy_signer::SignerSync::sign_hash_sync(s, &digest)?;
    Ok(Bytes::from(sig.as_bytes().to_vec()))
}

/// Sends a call to ComputeMarket: through the relay `(url, _)` when given, else paying gas.
fn submit(
    url: &str,
    s: &PrivateKeySigner,
    relay: Option<&(String, U256)>,
    data: Vec<u8>,
) -> Result<B256> {
    match relay {
        Some((r, _)) => crate::relay::through_relay(r, COMPUTE, data),
        None => send_tx(url, s, COMPUTE, U256::ZERO, data.into()),
    }
}

/// Which open jobs a provider takes.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenPolicy {
    /// Smallest wei per 1,000 input tokens.
    pub min_price_in: U256,
    /// Smallest wei per 1,000 output tokens.
    pub min_price_out: U256,
}

/// A provider's serving loop state.
pub struct Provider {
    signer: PrivateKeySigner,
    sk: bolt_vault::SecretKey,
    pk: bolt_vault::PublicKey,
    rpc: String,
    backend: String,
    models: HashMap<u64, String>,
    /// Take open jobs.
    open: Option<OpenPolicy>,
    /// Relay URL and fee per action.
    relay: Option<(String, U256)>,
    /// Top log-probabilities asked of the backend per output token (0: none).
    top_logprobs: u32,
    /// Jobs below this id are finished or not ours.
    cursor: u64,
    /// Jobs that failed permanently (not retried).
    failed: HashSet<u64>,
}

/// Parses `--model <id>=<name>` values.
pub fn parse_models(v: &[String]) -> Result<HashMap<u64, String>> {
    v.iter()
        .map(|m| {
            let (id, name) =
                m.split_once('=').with_context(|| format!("--model {m}: expected ID=NAME"))?;
            Ok((
                id.trim().parse::<u64>().with_context(|| format!("--model {m}"))?,
                name.trim().to_owned(),
            ))
        })
        .collect()
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider").field("address", &self.signer.address()).finish()
    }
}

impl Provider {
    /// A provider serving jobs addressed to `signer` with `backend`, paying its own gas.
    pub fn new(
        signer: PrivateKeySigner,
        rpc: &str,
        backend: &str,
        models: HashMap<u64, String>,
    ) -> Self {
        let (sk, pk) = vault_key(&signer);
        Self {
            signer,
            sk,
            pk,
            rpc: rpc.to_owned(),
            backend: backend.trim_end_matches('/').to_owned(),
            models,
            open: None,
            relay: None,
            top_logprobs: 5,
            cursor: 0,
            failed: HashSet::new(),
        }
    }

    /// Also takes open jobs under `policy`.
    pub fn with_open(mut self, policy: OpenPolicy) -> Self {
        self.open = Some(policy);
        self
    }

    /// Sends actions through the relay at `url`, offering `fee` wei each.
    pub fn with_relay(mut self, url: &str, fee: U256) -> Self {
        self.relay = Some((url.to_owned(), fee));
        self
    }

    /// Top log-probabilities asked per output token (0: none).
    pub fn with_top_logprobs(mut self, k: u32) -> Self {
        self.top_logprobs = k;
        self
    }

    fn relay_fee(&self) -> u128 {
        self.relay.as_ref().map(|(_, f)| f.to::<u128>()).unwrap_or(0)
    }

    /// One scan: take the jobs addressed to this provider (and open ones it wants), run the
    /// accepted ones whose input it can read, and deliver. Returns the jobs delivered.
    pub fn round(&mut self) -> Result<Vec<u64>> {
        let me = self.signer.address();
        let count = call(&self.rpc, IComputeMarket::jobCountCall {})?.to::<u64>();
        let now = chain_time(&self.rpc)?;
        let mut delivered = Vec::new();
        let mut advancing = true;
        for id in self.cursor..count {
            let j = call(&self.rpc, IComputeMarket::jobCall { id: U256::from(id) })?;
            let mine = j.provider == me;
            let live = matches!(j.state, state::OPEN | state::ACCEPTED) && j.deadline > now;
            if advancing && (!live || (!mine && j.provider != Address::ZERO)) {
                self.cursor = id + 1;
                continue;
            }
            advancing = false;
            let open_job = j.provider == Address::ZERO && j.state == state::OPEN;
            if !live || self.failed.contains(&id) || !(mine || (open_job && self.open.is_some())) {
                continue;
            }
            let Some(model) = self.models.get(&j.model).cloned() else {
                tracing::debug!(job = id, model = j.model, "model not served here");
                continue;
            };
            if open_job && !self.wants(&j)? {
                continue;
            }
            match self.serve(id, &j, &model) {
                Ok(true) => delivered.push(id),
                Ok(false) => {} // waiting for the requester to share the input
                Err(e) => {
                    eprintln!("job {id}: {e:#}");
                    self.failed.insert(id);
                }
            }
        }
        Ok(delivered)
    }

    /// Whether to take open job `j`: price and this provider's job limit.
    fn wants(&self, j: &IComputeMarket::Job) -> Result<bool> {
        let p = self.open.unwrap_or_default();
        if U256::from(j.priceIn) < p.min_price_in || U256::from(j.priceOut) < p.min_price_out {
            return Ok(false);
        }
        let limit = call(&self.rpc, IComputeMarket::jobLimitCall { p: self.signer.address() })?;
        Ok(U256::from(j.escrow) <= limit)
    }

    fn accept(&self, id: u64) -> Result<()> {
        let data = match &self.relay {
            None => IComputeMarket::acceptCall { id: U256::from(id) }.abi_encode(),
            Some(_) => {
                let fee = self.relay_fee();
                let deadline = chain_time(&self.rpc)? + 600;
                let sig = sign_action(
                    &self.rpc,
                    &self.signer,
                    "accept",
                    (U256::from(id), fee).abi_encode_params(),
                    deadline,
                )?;
                IComputeMarket::acceptForCall {
                    id: U256::from(id),
                    provider_: self.signer.address(),
                    fee,
                    deadline: U256::from(deadline),
                    sig,
                }
                .abi_encode()
            }
        };
        submit(&self.rpc, &self.signer, self.relay.as_ref(), data)?;
        Ok(())
    }

    /// Takes (if needed), runs and delivers job `id`. `Ok(false)`: its input is not readable yet
    /// (an open job whose requester has not shared it).
    fn serve(&self, id: u64, j: &IComputeMarket::Job, model: &str) -> Result<bool> {
        if j.state == state::OPEN {
            self.accept(id)?;
            println!("job {id}: accepted");
        }
        let j = call(&self.rpc, IComputeMarket::jobCall { id: U256::from(id) })?;
        let input = match fetch_and_open(&self.rpc, &j.input, &self.sk) {
            Ok(i) => i,
            Err(e) => {
                // Open jobs: the requester adds this provider as a recipient after acceptance.
                tracing::debug!(job = id, "input not readable yet: {e:#}");
                return Ok(false);
            }
        };
        let mut req: Value = serde_json::from_slice(&input).context("input is not JSON")?;
        let obj = req.as_object_mut().context("input is not a JSON object")?;
        obj.insert("model".into(), json!(model));
        obj.insert("stream".into(), json!(false));
        let cap = obj.get("max_tokens").and_then(Value::as_u64).unwrap_or(j.maxOut).min(j.maxOut);
        obj.insert("max_tokens".into(), json!(cap));
        if self.top_logprobs > 0 && !obj.contains_key("logprobs") {
            obj.insert("logprobs".into(), json!(true));
            obj.insert("top_logprobs".into(), json!(self.top_logprobs));
        }
        let url = format!("{}/v1/chat/completions", self.backend);
        let resp = match http_post_json(&url, &req, Duration::from_secs(900)) {
            Ok(r) => r,
            Err(e) if self.top_logprobs > 0 && obj_wants_logprobs(&req) => {
                // A backend without log-probabilities: answer without them.
                tracing::warn!(job = id, "backend refused logprobs ({e:#}); retrying without");
                let o = req.as_object_mut().expect("object");
                o.remove("logprobs");
                o.remove("top_logprobs");
                http_post_json(&url, &req, Duration::from_secs(900))?
            }
            Err(e) => return Err(e),
        };
        let tin = resp["usage"]["prompt_tokens"].as_u64().unwrap_or(0).min(j.maxIn);
        let tout = resp["usage"]["completion_tokens"].as_u64().unwrap_or(0).min(j.maxOut);
        let requester = encryption_key(&self.rpc, j.requester)
            .context("the requester has no encryption key (`job post` registers it)")?;
        let out = serde_json::to_vec(&resp)?;
        let env = seal_and_host(&self.rpc, &out, "output.json", &[requester, self.pk.clone()])?;
        let output = Bytes::from(env.to_bytes());
        let data = match &self.relay {
            None => IComputeMarket::deliverCall {
                id: U256::from(id),
                output,
                tokensIn: tin,
                tokensOut: tout,
            }
            .abi_encode(),
            Some(_) => {
                let fee = self.relay_fee();
                let deadline = chain_time(&self.rpc)? + 600;
                let sig = sign_action(
                    &self.rpc,
                    &self.signer,
                    "deliver",
                    (U256::from(id), output.clone(), tin, tout, fee).abi_encode_params(),
                    deadline,
                )?;
                IComputeMarket::deliverForCall {
                    id: U256::from(id),
                    provider_: self.signer.address(),
                    output,
                    tokensIn: tin,
                    tokensOut: tout,
                    fee,
                    deadline: U256::from(deadline),
                    sig,
                }
                .abi_encode()
            }
        };
        submit(&self.rpc, &self.signer, self.relay.as_ref(), data)?;
        println!("job {id}: delivered ({tin} input, {tout} output tokens)");
        Ok(true)
    }
}

fn obj_wants_logprobs(req: &Value) -> bool {
    req["logprobs"].as_bool().unwrap_or(false)
}

/// Registers `s` as a provider: directly, or through a relay that is repaid from the first
/// earnings.
pub fn register_provider(
    url: &str,
    s: &PrivateKeySigner,
    peer: &[u8],
    relay: Option<&(String, U256)>,
) -> Result<()> {
    let (_, pk) = vault_key(s);
    let key = B256::from(pk.to_bytes());
    let data = match relay {
        None => IComputeMarket::registerCall { encKey: key, peerId: Bytes::copy_from_slice(peer) }
            .abi_encode(),
        Some((_, fee)) => {
            let deadline = chain_time(url)? + 600;
            let peer = Bytes::copy_from_slice(peer);
            let sig = sign_action(
                url,
                s,
                "register",
                (key, peer.clone(), *fee).abi_encode_params(),
                deadline,
            )?;
            IComputeMarket::registerForCall {
                provider_: s.address(),
                encKey: key,
                peerId: peer,
                fee: *fee,
                deadline: U256::from(deadline),
                sig,
            }
            .abi_encode()
        }
    };
    submit(url, s, relay, data)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Disputes.

/// A copy of the envelope `env` (CID bytes) that also lets each of `to` read the file, handed to
/// the node; returns its CID. Only a current recipient (`sk`) can do this.
pub fn reshare(
    url: &str,
    env: &[u8],
    sk: &bolt_vault::SecretKey,
    to: &[bolt_vault::PublicKey],
) -> Result<Cid> {
    let root = Cid::try_from(env).context("envelope CID")?;
    let v = rpc(url, "bolt_getBlocks", json!([[root.to_string()], null, root.to_string()]))?;
    let got: Vec<Bytes> = serde_json::from_value(v)?;
    let mut e = bolt_vault::parse_envelope(got.first().context("envelope missing")?)?;
    let key = bolt_vault::open_key(&e, sk)?;
    let mut block = None;
    for pk in to {
        let b = bolt_vault::add_recipient(&e, &key, pk);
        e = bolt_vault::parse_envelope(&b.data)?;
        block = Some(b);
    }
    let b = block.context("no recipients to add")?;
    let cid = to_ipld(&b.cid);
    rpc(
        url,
        "bolt_hostBlocks",
        json!([cid.to_string(), [[cid.to_string(), hex::encode_prefixed(&b.data)]]]),
    )?;
    Ok(cid)
}

/// Shares a disputed job's files with its verifier panel. Returns how many panel members could
/// be given access (those whose verifier keys the node has heard).
pub fn share_dispute(url: &str, s: &PrivateKeySigner, id: u64) -> Result<usize> {
    let j = call(url, IComputeMarket::jobCall { id: U256::from(id) })?;
    if j.requester != s.address() {
        bail!("job {id} is not yours");
    }
    if j.state != state::DISPUTED {
        bail!("job {id} is not disputed ({})", state_name(j.state));
    }
    let d = call(url, IComputeMarket::disputesCall { id: U256::from(id) })?;
    if d.panelEpoch == 0 {
        bail!("no verifier panel yet: it is assigned at the next epoch");
    }
    let panel = call(url, IComputeMarket::panelCall { epoch: d.panelEpoch })?;
    let known: Vec<Option<String>> =
        serde_json::from_value(rpc(url, "bolt_verifierKeys", json!([panel]))?)?;
    let missing = known.iter().filter(|k| k.is_none()).count();
    if missing > 0 {
        // Every member must be able to read the files, or its node abstains (keys are announced
        // every minute).
        bail!(
            "the node has not heard {missing} of {} panel members' verifier keys yet; try again in a minute",
            panel.len()
        );
    }
    let keys: Vec<bolt_vault::PublicKey> = known
        .into_iter()
        .flatten()
        .map(|k| Ok(bolt_vault::PublicKey::from_bytes(&hex::decode(k)?)?))
        .collect::<Result<_>>()?;
    let (sk, _) = vault_key(s);
    let input = reshare(url, &j.input, &sk, &keys)?;
    let output = reshare(url, &j.output, &sk, &keys)?;
    let reason = reshare(url, &d.reason, &sk, &keys)?;
    let chain_id = u64::from_str_radix(
        rpc(url, "eth_chainId", json!([]))?.as_str().context("chain id")?.trim_start_matches("0x"),
        16,
    )?;
    let digest = crate::storage::DisputeShare::digest(
        chain_id,
        id,
        &input.to_bytes(),
        &output.to_bytes(),
        &reason.to_bytes(),
    );
    let sig = alloy_signer::SignerSync::sign_hash_sync(s, &digest)?;
    rpc(
        url,
        "bolt_shareDispute",
        json!([
            format!("0x{id:x}"),
            input.to_string(),
            output.to_string(),
            reason.to_string(),
            hex::encode_prefixed(sig.as_bytes())
        ]),
    )?;
    Ok(keys.len())
}

/// `boltchain judge`: a `--verifier-cmd` program that re-runs a disputed job.
#[derive(Debug, clap::Args)]
pub struct JudgeArgs {
    /// OpenAI-compatible backend (http only) to re-run the job on.
    #[arg(long)]
    pub backend: String,
    /// Model a job id maps to on the backend: `<id>=<name>` (repeatable).
    #[arg(long = "model", value_name = "ID=NAME", required = true)]
    pub models: Vec<String>,
    /// Smallest word overlap (Jaccard, 0–1) between the delivered answer and the re-run.
    #[arg(long, default_value_t = 0.3)]
    pub min_similarity: f64,
    /// Allowed excess of the claimed token counts over the recount (fraction).
    #[arg(long, default_value_t = 0.1)]
    pub token_slack: f64,
    /// Answers with log-probabilities: smallest mean overlap (Jaccard) of the top-k tokens per
    /// position between the delivery and the re-run.
    #[arg(long, default_value_t = 0.5)]
    pub min_topk_overlap: f64,
    /// Answers with log-probabilities: largest mean difference (nats) of the log-probabilities
    /// both runs give the same tokens.
    #[arg(long, default_value_t = 1.0)]
    pub logprob_tolerance: f64,
    /// Answers with log-probabilities: where the two runs first pick different tokens, the
    /// delivered token must be within this many nats of the re-run's best one (a near tie).
    #[arg(long, default_value_t = 2.0)]
    pub tie_gap: f64,
}

/// One output token with its log-probability and the top alternatives (OpenAI `logprobs`).
#[derive(Debug, Clone, PartialEq)]
pub struct TokenLogprobs {
    /// The token chosen.
    pub token: String,
    /// Its log-probability.
    pub logprob: f64,
    /// Top alternatives (token, log-probability), best first.
    pub top: Vec<(String, f64)>,
}

/// The per-token log-probabilities of a chat completion (`choices[0].logprobs.content`).
pub fn token_logprobs(resp: &Value) -> Option<Vec<TokenLogprobs>> {
    let content = resp["choices"][0]["logprobs"]["content"].as_array()?;
    content
        .iter()
        .map(|t| {
            Some(TokenLogprobs {
                token: t["token"].as_str()?.to_owned(),
                logprob: t["logprob"].as_f64()?,
                top: t["top_logprobs"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| {
                                Some((x["token"].as_str()?.to_owned(), x["logprob"].as_f64()?))
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// Limits for comparing a delivery's log-probabilities with a re-run's.
#[derive(Debug, Clone, Copy)]
pub struct LogprobLimits {
    /// Smallest mean top-k overlap.
    pub min_overlap: f64,
    /// Largest mean log-probability difference on shared tokens.
    pub tolerance: f64,
    /// Largest gap below the re-run's best token where the two runs part.
    pub tie_gap: f64,
}

/// Compares the delivered tokens with a greedy re-run of the same model, position by position
/// until the two runs pick different tokens (after that the contexts differ). A different
/// model, a smaller quantisation or invented numbers show as top-k sets that do not overlap,
/// log-probabilities far apart, or a parting token the re-run ranks low. Returns the notes, or
/// the reason the delivery is at fault.
pub fn compare_logprobs(
    delivered: &[TokenLogprobs],
    rerun: &[TokenLogprobs],
    limits: LogprobLimits,
) -> std::result::Result<String, String> {
    let set = |t: &TokenLogprobs| -> HashSet<String> {
        t.top.iter().map(|(x, _)| x.clone()).chain([t.token.clone()]).collect()
    };
    let lp = |t: &TokenLogprobs, tok: &str| -> Option<f64> {
        if t.token == tok {
            return Some(t.logprob);
        }
        t.top.iter().find(|(x, _)| x == tok).map(|(_, l)| *l)
    };
    let (mut overlap, mut diff, mut shared, mut n) = (0.0, 0.0, 0usize, 0usize);
    for (p, v) in delivered.iter().zip(rerun) {
        let (sp, sv) = (set(p), set(v));
        let union = sp.union(&sv).count().max(1);
        overlap += sp.intersection(&sv).count() as f64 / union as f64;
        n += 1;
        for tok in sp.intersection(&sv) {
            if let (Some(a), Some(b)) = (lp(p, tok), lp(v, tok)) {
                diff += (a - b).abs();
                shared += 1;
            }
        }
        if p.token != v.token {
            let best = v.top.first().map(|(_, l)| *l).unwrap_or(v.logprob).max(v.logprob);
            match lp(v, &p.token) {
                Some(l) if best - l <= limits.tie_gap => break,
                Some(l) => {
                    return Err(format!(
                        "at token {} the delivery chose {:?}, which the model ranks {:.2} nats below its best",
                        n - 1,
                        p.token,
                        best - l
                    ));
                }
                None => {
                    return Err(format!(
                        "at token {} the delivery chose {:?}, outside the model's top {}",
                        n - 1,
                        p.token,
                        sv.len()
                    ));
                }
            }
        }
    }
    if n == 0 {
        return Err("no tokens to compare".into());
    }
    let overlap = overlap / n as f64;
    let diff = if shared == 0 { 0.0 } else { diff / shared as f64 };
    let note = format!(
        "{n} tokens compared: top-k overlap {overlap:.2}, log-probability difference {diff:.2}"
    );
    if overlap < limits.min_overlap {
        return Err(format!("{note} (overlap below {:.2})", limits.min_overlap));
    }
    if diff > limits.tolerance {
        return Err(format!("{note} (difference above {:.2})", limits.tolerance));
    }
    Ok(note)
}

/// The first line of a verdict: `fault`, `ok`, or anything else to abstain; then the reasons.
pub type Verdict = (String, Vec<String>);

fn words(t: &str) -> HashSet<String> {
    t.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect()
}

/// Word-set overlap of two texts (1 when both are empty).
pub fn similarity(a: &str, b: &str) -> f64 {
    let (a, b) = (words(a), words(b));
    let union = a.union(&b).count();
    if union == 0 { 1.0 } else { a.intersection(&b).count() as f64 / union as f64 }
}

/// Tokens of `text` by the backend's `/tokenize` (llama.cpp), else about 4 characters each.
fn count_tokens(backend: &str, text: &str) -> u64 {
    http_post_json(
        &format!("{backend}/tokenize"),
        &json!({"content": text}),
        Duration::from_secs(60),
    )
    .ok()
    .and_then(|v| v["tokens"].as_array().map(|t| t.len() as u64))
    .unwrap_or_else(|| (text.chars().count() as u64).div_ceil(4))
}

/// Judges the disputed job described by the `BOLT_*` environment (see `CommandJudge`).
pub fn judge(args: &JudgeArgs, env: &HashMap<String, String>) -> Result<Verdict> {
    let get = |k: &str| env.get(k).cloned().with_context(|| format!("{k} not set"));
    let abstain = |why: String| Ok(("abstain".to_string(), vec![why]));
    if get("BOLT_SHARED")? != "1" {
        return abstain("the requester has not shared the files with the panel yet".into());
    }
    let url = get("BOLT_RPC")?;
    let backend = args.backend.trim_end_matches('/').to_owned();
    let models = parse_models(&args.models)?;
    let model_id: u64 = get("BOLT_MODEL")?.parse()?;
    let Some(model) = models.get(&model_id) else {
        return abstain(format!("model {model_id} is not served by this verifier"));
    };
    let sk = bolt_vault::SecretKey::from_bytes(&hex::decode(get("BOLT_VERIFIER_KEY")?)?)?;
    let cid = |k: &str| -> Result<Vec<u8>> { Ok(get(k)?.parse::<Cid>()?.to_bytes()) };
    let input = match fetch_and_open(&url, &cid("BOLT_INPUT")?, &sk) {
        Ok(i) => i,
        Err(e) => return abstain(format!("cannot read the input: {e:#}")),
    };
    let output = match fetch_and_open(&url, &cid("BOLT_OUTPUT")?, &sk) {
        Ok(o) => o,
        Err(e) => return abstain(format!("cannot read the output: {e:#}")),
    };
    let mut notes = Vec::new();
    let fault = |mut notes: Vec<String>, why: String| {
        notes.push(why);
        Ok(("fault".to_string(), notes))
    };
    let Ok(delivered) = serde_json::from_slice::<Value>(&output) else {
        return fault(notes, "the delivered output is not JSON".into());
    };
    let Some(answer) = delivered["choices"][0]["message"]["content"].as_str().map(str::to_owned)
    else {
        return fault(notes, "the delivered output has no answer".into());
    };
    let mut req: Value = serde_json::from_slice(&input).context("input is not JSON")?;
    let required = obj_wants_logprobs(&req);
    let delivered_lp = token_logprobs(&delivered);
    if required && delivered_lp.is_none() {
        return fault(
            notes,
            "the requester asked for log-probabilities and the delivery has none".into(),
        );
    }
    let obj = req.as_object_mut().context("input is not a JSON object")?;
    obj.insert("model".into(), json!(model));
    obj.insert("stream".into(), json!(false));
    obj.insert("temperature".into(), json!(0));
    if let Some(d) = &delivered_lp {
        // The delivered tokens must spell the delivered answer, and number what was charged.
        let spelled: String = d.iter().map(|t| t.token.as_str()).collect();
        if spelled.trim() != answer.trim() {
            return fault(
                notes,
                "the delivered log-probabilities do not spell the delivered answer".into(),
            );
        }
        let claimed_out: u64 = get("BOLT_TOKENS_OUT")?.parse()?;
        if claimed_out > d.len() as u64 {
            return fault(
                notes,
                format!("claimed {claimed_out} output tokens, the delivery lists {}", d.len()),
            );
        }
        let k = d.iter().map(|t| t.top.len()).max().unwrap_or(5).max(1);
        obj.insert("logprobs".into(), json!(true));
        obj.insert("top_logprobs".into(), json!(k));
        obj.insert("max_tokens".into(), json!(d.len()));
    }
    let rerun =
        http_post_json(&format!("{backend}/v1/chat/completions"), &req, Duration::from_secs(900))?;
    if let Some(d) = &delivered_lp {
        let claimed_in: u64 = get("BOLT_TOKENS_IN")?.parse()?;
        let slack = |n: u64| (n as f64 * (1.0 + args.token_slack)).ceil() as u64 + 8;
        if let Some(p) = rerun["usage"]["prompt_tokens"].as_u64()
            && claimed_in > slack(p)
        {
            return fault(notes, format!("claimed {claimed_in} input tokens, the prompt has {p}"));
        }
        let Some(v) = token_logprobs(&rerun) else {
            return abstain("the verifier's backend returns no log-probabilities".into());
        };
        let limits = LogprobLimits {
            min_overlap: args.min_topk_overlap,
            tolerance: args.logprob_tolerance,
            tie_gap: args.tie_gap,
        };
        return match compare_logprobs(d, &v, limits) {
            Ok(note) => {
                notes.push(note);
                Ok(("ok".to_string(), notes))
            }
            Err(why) => fault(notes, why),
        };
    }
    let again = rerun["choices"][0]["message"]["content"].as_str().unwrap_or_default().to_owned();
    let claimed_in: u64 = get("BOLT_TOKENS_IN")?.parse()?;
    let claimed_out: u64 = get("BOLT_TOKENS_OUT")?.parse()?;
    let slack = |n: u64| (n as f64 * (1.0 + args.token_slack)).ceil() as u64 + 8;
    if let Some(p) = rerun["usage"]["prompt_tokens"].as_u64()
        && claimed_in > slack(p)
    {
        return fault(notes, format!("claimed {claimed_in} input tokens, the prompt has {p}"));
    }
    let counted = count_tokens(&backend, &answer);
    if claimed_out > slack(counted) {
        return fault(
            notes,
            format!("claimed {claimed_out} output tokens, the answer has about {counted}"),
        );
    }
    let sim = similarity(&answer, &again);
    notes.push(format!("similarity to the re-run {sim:.2}"));
    if sim < args.min_similarity {
        return fault(
            notes,
            format!("the answer differs from the re-run (below {:.2})", args.min_similarity),
        );
    }
    Ok(("ok".to_string(), notes))
}

// ---------------------------------------------------------------------------------------------
// Commands.

/// Runs a provider command.
pub fn run_provider(cmd: ProviderCmd) -> Result<()> {
    match cmd {
        ProviderCmd::Register { wallet, node_key, rpc: url, relay } => {
            let s = load_wallet(&wallet)?;
            let peer = bolt_net::load_or_create_key(&node_key)?.public().to_peer_id();
            register_provider(&url, &s, &peer.to_bytes(), relay.resolve()?.as_ref())?;
            println!("{} registered as a compute provider (peer {peer})", s.address());
        }
        ProviderCmd::Run {
            wallet,
            backend,
            models,
            rpc: url,
            interval,
            open,
            min_price_in,
            min_price_out,
            top_logprobs,
            relay,
        } => {
            let s = load_wallet(&wallet)?;
            let models = parse_models(&models)?;
            let reg = call(&url, IComputeMarket::providerCall { p: s.address() })?;
            if !reg.registered {
                bail!("{} is not registered: run `boltchain provider register` first", s.address());
            }
            for id in models.keys() {
                if !call(&url, IModelRegistry::existsCall { id: *id })? {
                    bail!("model {id} is not in ModelRegistry (`boltchain model list`)");
                }
            }
            println!("serving jobs for {} with {backend} (models {models:?})", s.address());
            let mut p = Provider::new(s, &url, &backend, models).with_top_logprobs(top_logprobs);
            if open {
                p = p.with_open(OpenPolicy {
                    min_price_in: parse_bolt(&min_price_in)?,
                    min_price_out: parse_bolt(&min_price_out)?,
                });
            }
            if let Some((r, fee)) = relay.resolve()? {
                p = p.with_relay(&r, fee);
            }
            loop {
                if let Err(e) = p.round() {
                    eprintln!("scan: {e:#}");
                }
                std::thread::sleep(Duration::from_secs(interval));
            }
        }
        ProviderCmd::Status { address, rpc: url } => {
            let p = call(&url, IComputeMarket::providerCall { p: address })?;
            let limit = call(&url, IComputeMarket::jobLimitCall { p: address })?;
            let bal = call(&url, IComputeMarket::balanceOfCall { account: address })?;
            println!(
                "{address}: {}registered, bond {} BOLT, job limit {} BOLT, {} jobs done, {} faults, balance {} BOLT{}",
                if p.registered { "" } else { "not " },
                format_bolt(p.bond),
                format_bolt(limit),
                p.jobsDone,
                p.faults,
                format_bolt(bal),
                if p.debt.is_zero() {
                    String::new()
                } else {
                    format!(", debt {} BOLT", format_bolt(p.debt))
                }
            );
        }
        ProviderCmd::Collect { wallet, rpc: url, relay } => {
            let s = load_wallet(&wallet)?;
            let relay = relay.resolve()?;
            let count = call(&url, IComputeMarket::jobCountCall {})?.to::<u64>();
            let now = chain_time(&url)?;
            for id in 0..count {
                let j = call(&url, IComputeMarket::jobCall { id: U256::from(id) })?;
                if j.provider == s.address()
                    && j.state == state::DELIVERED
                    && now >= j.deliveredAt + j.window
                {
                    let data = IComputeMarket::settleCall { id: U256::from(id) }.abi_encode();
                    match submit(&url, &s, relay.as_ref(), data) {
                        Ok(_) => println!("job {id}: settled"),
                        Err(e) => println!("job {id}: {e:#}"),
                    }
                }
            }
            match &relay {
                // The relay pushes the balance to the provider (no gas needed here).
                Some(_) => {
                    let b = call(&url, IComputeMarket::balanceOfCall { account: s.address() })?;
                    if b.is_zero() {
                        println!("nothing to withdraw");
                    } else {
                        let data = IComputeMarket::payoutCall { account: s.address() }.abi_encode();
                        submit(&url, &s, relay.as_ref(), data)?;
                        println!("paid out {} BOLT", format_bolt(b));
                    }
                }
                None => withdraw(&url, &s)?,
            }
        }
    }
    Ok(())
}

fn withdraw(url: &str, s: &PrivateKeySigner) -> Result<()> {
    let b = call(url, IComputeMarket::balanceOfCall { account: s.address() })?;
    if b.is_zero() {
        println!("nothing to withdraw");
        return Ok(());
    }
    let data = IComputeMarket::withdrawCall { to: s.address() }.abi_encode();
    send_tx(url, s, COMPUTE, U256::ZERO, data.into())?;
    println!("withdrew {} BOLT", format_bolt(b));
    Ok(())
}

/// Parameters of a new job.
#[derive(Debug, Clone)]
pub struct NewJob {
    /// Provider.
    pub provider: Address,
    /// Model id.
    pub model: u64,
    /// Request JSON (`{"messages": ...}`).
    pub request: Value,
    /// Wei per 1,000 input tokens.
    pub price_in: U256,
    /// Wei per 1,000 output tokens.
    pub price_out: U256,
    /// Input token cap.
    pub max_in: u64,
    /// Output token cap.
    pub max_out: u64,
    /// Seconds to deliver.
    pub deadline: u64,
    /// Seconds to dispute.
    pub window: u64,
}

/// Encrypts the request for the provider (only for the requester when the job is open: the
/// provider that takes it is added later, see [`share_input`]), hands it to the node, registers
/// the requester's own encryption key if needed, and posts the job. Returns its id.
pub fn post_job(url: &str, s: &PrivateKeySigner, job: &NewJob) -> Result<u64> {
    let (_, mine) = vault_key(s);
    let mut recipients = vec![mine.clone()];
    if job.provider != Address::ZERO {
        recipients.push(encryption_key(url, job.provider)?);
    }
    // The provider encrypts the result for the requester's registered key.
    let have = call(url, IComputeMarket::encryptionKeyCall { account: s.address() })?;
    if have != B256::from(mine.to_bytes()) {
        let data =
            IComputeMarket::setEncryptionKeyCall { key: B256::from(mine.to_bytes()) }.abi_encode();
        send_tx(url, s, COMPUTE, U256::ZERO, data.into())?;
    }
    let body = serde_json::to_vec(&job.request)?;
    let env = seal_and_host(url, &body, "input.json", &recipients)?;
    let now = chain_time(url)?;
    let cost = |t: u64, p: U256| U256::from(t) * p / U256::from(1000);
    let value = cost(job.max_in, job.price_in) + cost(job.max_out, job.price_out);
    let data = IComputeMarket::postCall {
        provider_: job.provider,
        model: job.model,
        input: Bytes::from(env.to_bytes()),
        priceIn: job.price_in.to::<u128>(),
        priceOut: job.price_out.to::<u128>(),
        maxIn: job.max_in,
        maxOut: job.max_out,
        deadline: now + job.deadline,
        window: job.window,
        relayFee: 0,
    }
    .abi_encode();
    println!("escrow {} BOLT", format_bolt(value));
    let hash = send_tx(url, s, COMPUTE, value, data.into())?;
    Ok(first_indexed(url, hash, "JobPosted(uint256,address,address,uint64,bytes)")?.to::<u64>())
}

/// Adds the provider that took open job `id` as a recipient of its input (no re-upload) and
/// publishes the new envelope (`shareInput`).
pub fn share_input(url: &str, s: &PrivateKeySigner, id: u64) -> Result<()> {
    let j = call(url, IComputeMarket::jobCall { id: U256::from(id) })?;
    if j.requester != s.address() {
        bail!("job {id} is not yours");
    }
    if j.state != state::ACCEPTED {
        bail!("job {id} is {}, not accepted", state_name(j.state));
    }
    let (sk, _) = vault_key(s);
    let provider = encryption_key(url, j.provider)?;
    let env = reshare(url, &j.input, &sk, &[provider])?;
    let data =
        IComputeMarket::shareInputCall { id: U256::from(id), input: Bytes::from(env.to_bytes()) }
            .abi_encode();
    send_tx(url, s, COMPUTE, U256::ZERO, data.into())?;
    Ok(())
}

/// Follows job `id` until it is delivered (sharing its input with the provider that takes it
/// if it was open) and returns the result, or fails when it ends otherwise.
pub fn watch_job(url: &str, s: &PrivateKeySigner, id: u64, poll: Duration) -> Result<Value> {
    let (sk, _) = vault_key(s);
    let mut shared = false;
    loop {
        let j = call(url, IComputeMarket::jobCall { id: U256::from(id) })?;
        match j.state {
            state::ACCEPTED if !shared => {
                // Posted open, the input has one recipient (the requester); addressed jobs and
                // shared ones have two.
                let readable = bolt_vault::parse_envelope(&fetch_envelope(url, &j.input)?)
                    .map(|e| e.keys.len() >= 2)
                    .unwrap_or(false);
                if !readable {
                    share_input(url, s, id)?;
                    println!("job {id}: input shared with provider {}", j.provider);
                }
                shared = true;
            }
            state::DELIVERED | state::SETTLED | state::DISPUTED => {
                let out = fetch_and_open(url, &j.output, &sk)?;
                return Ok(serde_json::from_slice(&out)?);
            }
            state::REFUNDED => bail!("job {id} was refunded"),
            _ => {}
        }
        std::thread::sleep(poll);
    }
}

fn fetch_envelope(url: &str, env: &[u8]) -> Result<Vec<u8>> {
    let root = Cid::try_from(env).context("envelope CID")?;
    let v = rpc(url, "bolt_getBlocks", json!([[root.to_string()], null, root.to_string()]))?;
    let got: Vec<Bytes> = serde_json::from_value(v)?;
    Ok(got.into_iter().next().context("envelope missing")?.to_vec())
}

/// Fetches and decrypts a delivered job's result.
pub fn job_result(url: &str, s: &PrivateKeySigner, id: u64) -> Result<Value> {
    let j = call(url, IComputeMarket::jobCall { id: U256::from(id) })?;
    if j.output.is_empty() {
        bail!("job {id} has no result yet ({})", state_name(j.state));
    }
    let (sk, _) = vault_key(s);
    let out = fetch_and_open(url, &j.output, &sk)?;
    Ok(serde_json::from_slice(&out)?)
}

fn print_result(v: &Value) {
    match v["choices"][0]["message"]["content"].as_str() {
        Some(text) => println!("{text}"),
        None => println!("{}", serde_json::to_string_pretty(v).unwrap_or_default()),
    }
}

/// Model registry commands (ADR 0011 §7).
#[derive(Debug, clap::Subcommand)]
pub enum ModelCmd {
    /// Register a model (anyone may; entries are permanent). Prints its id.
    Register {
        /// Account key file (pays the gas).
        #[arg(long)]
        wallet: PathBuf,
        /// Display name, e.g. "Qwen2.5-7B-Instruct Q4_K_M".
        #[arg(long)]
        name: String,
        /// CID of the weights file (e.g. the GGUF), as stored with `boltchain storage put`.
        #[arg(long)]
        weights: String,
        /// CID of the tokenizer, when it is not inside the weights file.
        #[arg(long)]
        tokenizer: Option<String>,
        /// Runtime and version that should serve it, e.g. "llama.cpp b4500".
        #[arg(long)]
        runtime: String,
        /// Parameter count, e.g. 7.6e9.
        #[arg(long)]
        parameters: f64,
        /// Suggested GPU memory, MiB.
        #[arg(long)]
        vram: u32,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// List registered models and how many providers serve each.
    List {
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
    /// Declare that this provider serves a model (or stops, with `--stop`).
    Support {
        /// Account key file (the provider).
        #[arg(long)]
        wallet: PathBuf,
        /// Model id.
        id: u64,
        /// Stop serving it.
        #[arg(long)]
        stop: bool,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = RPC)]
        rpc: String,
    },
}

fn models_call<C: SolCall>(url: &str, c: C) -> Result<C::Return> {
    let out = rpc(
        url,
        "eth_call",
        json!([{"to": MODELS, "data": hex::encode_prefixed(c.abi_encode())}, "latest"]),
    )?;
    let bytes: Bytes = serde_json::from_value(out)?;
    Ok(C::abi_decode_returns(&bytes)?)
}

/// Runs a model command.
pub fn run_model(cmd: ModelCmd) -> Result<()> {
    match cmd {
        ModelCmd::Register {
            wallet,
            name,
            weights,
            tokenizer,
            runtime,
            parameters,
            vram,
            rpc: url,
        } => {
            let s = load_wallet(&wallet)?;
            let cid = |c: &str| -> Result<Bytes> {
                Ok(Bytes::from(c.parse::<Cid>().with_context(|| format!("CID {c}"))?.to_bytes()))
            };
            let data = IModelRegistry::registerCall {
                name: name.clone(),
                weights: cid(&weights)?,
                tokenizer: tokenizer.as_deref().map(cid).transpose()?.unwrap_or_default(),
                runtime,
                parameters: parameters as u64,
                vramMiB: vram,
            }
            .abi_encode();
            let hash = send_tx(&url, &s, MODELS, U256::ZERO, data.into())?;
            let id = first_indexed(&url, hash, "ModelRegistered(uint64,address,string,bytes)")?;
            println!("model {id} registered: {name}");
        }
        ModelCmd::List { rpc: url } => {
            let n = models_call(&url, IModelRegistry::modelCountCall {})?.to::<u64>();
            if n == 0 {
                println!("no models registered");
            }
            for id in 1..=n {
                let m = models_call(&url, IModelRegistry::modelCall { id })?;
                let providers = models_call(&url, IModelRegistry::providerCountCall { id })?;
                let weights = Cid::try_from(m.weights.as_ref())
                    .map(|c| c.to_string())
                    .unwrap_or_else(|_| hex::encode_prefixed(&m.weights));
                println!(
                    "{id}: {} — {:.1}B parameters, {} MiB, {} — weights {weights} — {providers} provider(s)",
                    m.name,
                    m.parameters as f64 / 1e9,
                    m.vramMiB,
                    m.runtime
                );
            }
        }
        ModelCmd::Support { wallet, id, stop, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IModelRegistry::setSupportCall { id, serving: !stop }.abi_encode();
            send_tx(&url, &s, MODELS, U256::ZERO, data.into())?;
            println!(
                "{} {} model {id}",
                s.address(),
                if stop { "no longer serves" } else { "serves" }
            );
        }
    }
    Ok(())
}

/// Runs a job command.
pub fn run_job(cmd: JobCmd) -> Result<()> {
    match cmd {
        JobCmd::Post {
            wallet,
            provider,
            model,
            prompt,
            input,
            price_in,
            price_out,
            max_in,
            max_out,
            deadline,
            window,
            wait,
            logprobs,
            rpc: url,
        } => {
            let s = load_wallet(&wallet)?;
            if !call(&url, IModelRegistry::existsCall { id: model })? {
                bail!("model {model} is not in ModelRegistry (`boltchain model list`)");
            }
            let mut request: Value = match (prompt, input) {
                (Some(p), _) => json!({"messages": [{"role": "user", "content": p}]}),
                (None, Some(f)) => serde_json::from_slice(&std::fs::read(&f)?)
                    .with_context(|| format!("{} is not JSON", f.display()))?,
                (None, None) => bail!("give --prompt or --input"),
            };
            request.as_object_mut().context("the request must be a JSON object")?.remove("model");
            request["max_tokens"] = json!(max_out);
            if logprobs {
                request["logprobs"] = json!(true);
                request["top_logprobs"] = json!(5);
            }
            let job = NewJob {
                provider: provider.unwrap_or(Address::ZERO),
                model,
                request,
                price_in: parse_bolt(&price_in)?,
                price_out: parse_bolt(&price_out)?,
                max_in,
                max_out,
                deadline: deadline * 60,
                window: window * 60,
            };
            let id = post_job(&url, &s, &job)?;
            if provider.is_none() {
                println!("job {id} posted, open to any provider");
            } else {
                println!("job {id} posted");
            }
            if wait {
                print_result(&watch_job(&url, &s, id, Duration::from_secs(3))?);
            } else if provider.is_none() {
                println!("run `boltchain job watch {id}` to share the input with whoever takes it");
            } else {
                println!("follow it with `boltchain job status {id}`");
            }
        }
        JobCmd::Watch { wallet, id, rpc: url } => {
            let s = load_wallet(&wallet)?;
            print_result(&watch_job(&url, &s, id, Duration::from_secs(3))?);
        }
        JobCmd::Status { id, rpc: url } => {
            let j = call(&url, IComputeMarket::jobCall { id: U256::from(id) })?;
            if j.requester == Address::ZERO {
                bail!("no job {id}");
            }
            let cost = |t: u64, p: u128| U256::from(t) * U256::from(p) / U256::from(1000);
            println!("job {id}: {}", state_name(j.state));
            println!("  requester {}, provider {}, model {}", j.requester, j.provider, j.model);
            println!(
                "  price {} / {} BOLT per 1K tokens (in / out), escrow {} BOLT",
                format_bolt(U256::from(j.priceIn)),
                format_bolt(U256::from(j.priceOut)),
                format_bolt(U256::from(j.escrow))
            );
            if j.state >= state::DELIVERED {
                println!(
                    "  delivered {} input + {} output tokens, cost {} BOLT",
                    j.tokensIn,
                    j.tokensOut,
                    format_bolt(cost(j.tokensIn, j.priceIn) + cost(j.tokensOut, j.priceOut))
                );
            }
            if j.state == state::DELIVERED {
                println!("  dispute window ends at {} (unix)", j.deliveredAt + j.window);
            }
            if j.state == state::DISPUTED {
                let d = call(&url, IComputeMarket::disputesCall { id: U256::from(id) })?;
                if d.panelEpoch == 0 {
                    println!("  waiting for a verifier panel (next epoch)");
                } else {
                    println!("  decided by the verifier panel of epoch {}", d.panelEpoch);
                }
            }
        }
        JobCmd::Result { wallet, id, out, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let v = job_result(&url, &s, id)?;
            if let Some(f) = out {
                std::fs::write(&f, serde_json::to_vec_pretty(&v)?)?;
                println!("saved to {}", f.display());
            }
            print_result(&v);
        }
        JobCmd::Approve { wallet, id, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IComputeMarket::settleCall { id: U256::from(id) }.abi_encode();
            send_tx(&url, &s, COMPUTE, U256::ZERO, data.into())?;
            println!("job {id} paid; the rest of the escrow is in your balance (`job withdraw`)");
        }
        JobCmd::Dispute { wallet, id, reason, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let (_, mine) = vault_key(&s);
            let body = serde_json::to_vec(&json!({"job": id, "reason": reason}))?;
            let env = seal_and_host(&url, &body, "dispute.json", &[mine])?;
            let data = IComputeMarket::disputeCall {
                id: U256::from(id),
                reason: Bytes::from(env.to_bytes()),
            }
            .abi_encode();
            send_tx(&url, &s, COMPUTE, U256::from(10u128.pow(18)), data.into())?;
            println!("job {id} disputed; a verifier panel is assigned at the next epoch, then run");
            println!(
                "`boltchain job share --wallet <wallet> {id}` so the panel can read the files"
            );
        }
        JobCmd::Share { wallet, id, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let n = share_dispute(&url, &s, id)?;
            println!("job {id}: files shared with {n} panel members");
        }
        JobCmd::Refund { wallet, id, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let data = IComputeMarket::refundCall { id: U256::from(id) }.abi_encode();
            send_tx(&url, &s, COMPUTE, U256::ZERO, data.into())?;
            println!("job {id} refunded to your balance (`job withdraw`)");
        }
        JobCmd::Withdraw { wallet, rpc: url } => {
            let s = load_wallet(&wallet)?;
            withdraw(&url, &s)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similarity_of_answers() {
        assert_eq!(similarity("Hello, world!", "hello world"), 1.0);
        assert!(similarity("the cat sat", "a dog ran") < 0.1);
        assert!((similarity("a b c d", "a b x y") - 2.0 / 6.0).abs() < 1e-9);
        assert_eq!(similarity("", ""), 1.0);
    }

    type Spec<'a> = (&'a str, f64, &'a [(&'a str, f64)]);

    fn toks(spec: &[Spec]) -> Vec<TokenLogprobs> {
        spec.iter()
            .map(|(t, l, top)| TokenLogprobs {
                token: t.to_string(),
                logprob: *l,
                top: top.iter().map(|(x, y)| (x.to_string(), *y)).collect(),
            })
            .collect()
    }

    const LIMITS: LogprobLimits = LogprobLimits { min_overlap: 0.5, tolerance: 1.0, tie_gap: 2.0 };

    #[test]
    fn logprobs_of_the_same_model_agree() {
        // Another GPU: probabilities move a little, and the runs part at a near tie.
        let delivered = toks(&[
            ("The", -0.1, &[("The", -0.1), ("A", -2.5), ("This", -3.0)]),
            (" sky", -0.3, &[(" sky", -0.3), (" sea", -1.6), (" sun", -3.2)]),
            (" is", -0.05, &[(" is", -0.05), (" was", -3.1), (" looks", -4.0)]),
        ]);
        let rerun = toks(&[
            ("The", -0.12, &[("The", -0.12), ("A", -2.4), ("This", -3.1)]),
            (" sea", -0.9, &[(" sea", -0.9), (" sky", -1.1), (" sun", -3.0)]),
        ]);
        let note = compare_logprobs(&delivered, &rerun, LIMITS).unwrap();
        assert!(note.starts_with("2 tokens compared"), "{note}");
    }

    #[test]
    fn logprobs_of_another_model_or_invented_ones_are_caught() {
        let rerun = toks(&[
            ("Paris", -0.05, &[("Paris", -0.05), ("The", -3.5), ("It", -4.0)]),
            (".", -0.2, &[(".", -0.2), (",", -2.0), ("!", -4.0)]),
        ]);
        // A token the model does not consider.
        let other = toks(&[("Lyon", -0.1, &[("Lyon", -0.1), ("Paris", -2.6), ("Nice", -3.0)])]);
        let why = compare_logprobs(&other, &rerun, LIMITS).unwrap_err();
        assert!(why.contains("outside the model's top"), "{why}");
        // A token the model ranks far below its best.
        let low = toks(&[("It", -0.1, &[("It", -0.1), ("Paris", -2.5)])]);
        let why = compare_logprobs(&low, &rerun, LIMITS).unwrap_err();
        assert!(why.contains("nats below its best"), "{why}");
        // Same tokens, made-up probabilities.
        let made_up = toks(&[
            ("Paris", -2.9, &[("Paris", -2.9), ("The", -0.5), ("It", -0.7)]),
            (".", -2.5, &[(".", -2.5), (",", -0.1), ("!", -0.2)]),
        ]);
        let why = compare_logprobs(&made_up, &rerun, LIMITS).unwrap_err();
        assert!(why.contains("difference above"), "{why}");
        // Other candidates entirely (a different model agreeing on the first word).
        let alien = toks(&[
            ("Paris", -0.05, &[("Paris", -0.05), ("Berlin", -3.5), ("Rome", -4.0), ("Oslo", -4.5)]),
            (".", -0.2, &[(".", -0.2), (";", -2.0), ("?", -4.0), (":", -4.4)]),
        ]);
        let why = compare_logprobs(&alien, &rerun, LIMITS).unwrap_err();
        assert!(why.contains("overlap below"), "{why}");
    }

    #[test]
    fn logprobs_parse_from_openai_responses() {
        let v = json!({"choices": [{"logprobs": {"content": [
            {"token": "Hi", "logprob": -0.5, "bytes": [72, 105], "top_logprobs": [{"token": "Hi", "logprob": -0.5}, {"token": "Hello", "logprob": -1.2}]}
        ]}}]});
        let t = token_logprobs(&v).unwrap();
        assert_eq!(t[0].token, "Hi");
        assert_eq!(t[0].top[1], ("Hello".to_string(), -1.2));
        assert!(token_logprobs(&json!({"choices": [{"message": {}}]})).is_none());
    }

    #[test]
    fn model_maps_parse() {
        let m = parse_models(&["1=qwen2.5-7b".into(), " 2 = llama3 ".into()]).unwrap();
        assert_eq!(m[&1], "qwen2.5-7b");
        assert_eq!(m[&2], "llama3");
        assert!(parse_models(&["x=y".into()]).is_err());
        assert!(parse_models(&["1".into()]).is_err());
    }
}
