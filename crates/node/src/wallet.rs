//! Minimal wallet for operators (no MetaMask needed on a server): create an account key, check
//! balances, send BOLT, stake a validator key and publish a validator's history peer, through
//! any node's JSON-RPC.

use crate::keys;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, hex};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use anyhow::{Context, Result, bail};
use bolt_primitives::params::WEI_PER_BOLT;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

/// Wallet commands.
#[derive(Debug, clap::Subcommand)]
pub enum WalletCmd {
    /// Create a new account key file (0600; refuses to overwrite).
    New {
        /// Output file: a Web3 Secret Storage v3 keystore (the geth / MetaMask format) encrypted
        /// with a password (asked on the terminal, or `BOLT_PASSWORD_FILE`).
        #[arg(long)]
        out: PathBuf,
        /// Write the key unencrypted instead (test machines only).
        #[arg(long)]
        plain: bool,
    },
    /// Encrypt an existing plain account file into a new v3 keystore (the plain file is left in
    /// place: delete it once the new one works).
    Encrypt {
        /// Plain account file.
        #[arg(long)]
        wallet: PathBuf,
        /// Output keystore.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print an account's address and balance.
    Balance {
        /// Account key file (or use --address).
        #[arg(long)]
        wallet: Option<PathBuf>,
        /// Address.
        #[arg(long)]
        address: Option<Address>,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Send BOLT (and optionally call data).
    Send {
        /// Account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// Recipient.
        #[arg(long)]
        to: Address,
        /// Amount in BOLT (decimals allowed).
        #[arg(long, default_value = "0")]
        value: String,
        /// Call data (hex).
        #[arg(long)]
        data: Option<Bytes>,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Register a validator key with a stake (at least 64 BOLT) paid by this account, which
    /// becomes the validator's owner.
    Stake {
        /// Account key file (owner; pays the stake).
        #[arg(long)]
        wallet: PathBuf,
        /// BLS validator key file.
        #[arg(long)]
        key: PathBuf,
        /// Stake in BOLT.
        #[arg(long)]
        amount: String,
        /// Receives rewards and tips (defaults to the owner).
        #[arg(long)]
        fee_recipient: Option<Address>,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Publish the node a validator serves history from (ADR 0009); send from the owner.
    SetPeer {
        /// Owner account key file.
        #[arg(long)]
        wallet: PathBuf,
        /// BLS validator key file (its id is looked up on chain).
        #[arg(long)]
        key: PathBuf,
        /// The node's identity key (`<datadir>/node.key`).
        #[arg(long)]
        node_key: PathBuf,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Deploy the evidence certificates contract (ADR 0016) from this account and print its
    /// address; then run the explorer node with `--certificates <address>`.
    DeployCertificates {
        /// Account key file (pays the gas).
        #[arg(long)]
        wallet: PathBuf,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Register this account as a storage provider without stake (ADR 0012), serving history
    /// from the node key's peer id. Needs a little BOLT for gas; with `--signed` it only prints a
    /// signed registration that anyone can submit for you (`wallet send --to <to> --data <data>`).
    /// Then run the node with `--storage-account <address>`.
    StorageRegister {
        /// Account key file (receives the storage rewards).
        #[arg(long)]
        wallet: PathBuf,
        /// The node's identity key (`<datadir>/node.key`).
        #[arg(long)]
        node_key: PathBuf,
        /// Print a signed registration for a relayer instead of sending it.
        #[arg(long)]
        signed: bool,
        /// JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletFile {
    address: Address,
    private_key: String,
}

/// Loads an account key file (v3 keystore or plain).
pub fn load_wallet(path: &Path) -> Result<PrivateKeySigner> {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    if crate::keystore::is_encrypted(&v) {
        let s = crate::keystore::unlock(&format!("account {}", path.display()), |p| {
            let key = crate::keystore::v3_decrypt(&v, p)?;
            PrivateKeySigner::from_slice(&key).context("invalid private key")
        })?;
        if let Some(a) = v.get("address").and_then(Value::as_str)
            && a.trim_start_matches("0x").to_lowercase() != hex::encode(s.address())
        {
            bail!("keystore address does not match its key");
        }
        return Ok(s);
    }
    let f: WalletFile = serde_json::from_value(v)?;
    let s: PrivateKeySigner = f.private_key.parse().context("invalid private key")?;
    if s.address() != f.address {
        bail!("wallet file address does not match its key");
    }
    Ok(s)
}

fn write_wallet(out: &Path, s: &PrivateKeySigner, encrypt: bool) -> Result<()> {
    if out.exists() {
        bail!("{} already exists; refusing to overwrite a key", out.display());
    }
    let json = if encrypt {
        let password = crate::keystore::password(&format!("new account {}", out.display()), true)?;
        crate::keystore::v3_encrypt(&s.to_bytes()[..], s.address().as_slice(), &password)?
    } else {
        serde_json::to_value(WalletFile {
            address: s.address(),
            private_key: hex::encode_prefixed(s.to_bytes()),
        })?
    };
    crate::keys::write_secret(out, &serde_json::to_string_pretty(&json)?)
}

/// Parses a decimal BOLT amount into wei.
pub fn parse_bolt(s: &str) -> Result<U256> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > 18 || int.is_empty() && frac.is_empty() {
        bail!("invalid amount {s}");
    }
    let frac = format!("{frac:0<18}");
    let int = if int.is_empty() { U256::ZERO } else { U256::from_str_radix(int, 10)? };
    Ok(int * U256::from(WEI_PER_BOLT) + U256::from_str_radix(&frac, 10)?)
}

/// Formats wei as BOLT.
pub fn format_bolt(wei: U256) -> String {
    let w = U256::from(WEI_PER_BOLT);
    let frac = format!("{:018}", wei % w).trim_end_matches('0').to_string();
    if frac.is_empty() { format!("{}", wei / w) } else { format!("{}.{frac}", wei / w) }
}

/// A plain HTTP/1.1 request (`http://` only); returns the status and the body (Content-Length
/// or read to close; chunked bodies are de-chunked).
pub fn http(method: &str, url: &str, body: Option<&[u8]>, timeout: Duration) -> Result<(u16, Vec<u8>)> {
    let rest = url.strip_prefix("http://").context("only http:// endpoints are supported")?;
    let (host, path) =
        rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let addr = std::net::ToSocketAddrs::to_socket_addrs(host)?
        .next()
        .with_context(|| format!("resolving {host}"))?;
    let mut s = std::net::TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("connecting to {host}"))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let body = body.unwrap_or_default();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    s.write_all(body)?;
    let mut resp = Vec::new();
    s.take(64 << 20).read_to_end(&mut resp)?;
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").context("bad HTTP response")?;
    let head = String::from_utf8_lossy(&resp[..split]).to_string();
    let mut data = resp[split + 4..].to_vec();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .context("bad HTTP status line")?;
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut p = 0;
        while let Some(e) = data[p..].windows(2).position(|w| w == b"\r\n") {
            let n = usize::from_str_radix(String::from_utf8_lossy(&data[p..p + e]).trim(), 16)
                .context("chunk size")?;
            p += e + 2;
            if n == 0 || p + n > data.len() {
                break;
            }
            out.extend_from_slice(&data[p..p + n]);
            p += n + 2;
        }
        data = out;
    }
    Ok((status, data))
}

/// One JSON-RPC call over plain HTTP (`http://host:port[/path]`).
pub fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let rest = url.strip_prefix("http://").context("only http:// endpoints are supported")?;
    let (host, path) =
        rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let mut s =
        std::net::TcpStream::connect(host).with_context(|| format!("connecting to {host}"))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    let json_body = resp.split_once("\r\n\r\n").map(|(_, b)| b).context("bad HTTP response")?;
    // Chunked responses: take the JSON object between the first '{' and the last '}'.
    let start = json_body.find('{').context("no JSON in response")?;
    let end = json_body.rfind('}').context("no JSON in response")?;
    let v: Value = serde_json::from_str(&json_body[start..=end])?;
    if let Some(e) = v.get("error") {
        bail!("{method}: {}", e.get("message").and_then(|m| m.as_str()).unwrap_or("error"));
    }
    Ok(v["result"].clone())
}

fn quantity(v: &Value) -> Result<U256> {
    let s = v.as_str().context("expected a hex quantity")?;
    Ok(U256::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

/// Largest gas limit a transaction may have (EIP-7825).
pub const TX_GAS_CAP: u64 = 1 << 24;

/// Delegates `signer`'s account to `delegate` (EIP-7702) and calls the account itself with
/// `data` in the same transaction; waits for its receipt.
pub fn send_delegated(
    rpc_url: &str,
    signer: &PrivateKeySigner,
    delegate: Address,
    data: Bytes,
) -> Result<B256> {
    use alloy_consensus::TxEip7702;
    use alloy_eips::eip7702::Authorization;
    use alloy_signer::SignerSync;
    let from = signer.address();
    let chain_id = quantity(&rpc(rpc_url, "eth_chainId", json!([]))?)?.to::<u64>();
    let nonce =
        quantity(&rpc(rpc_url, "eth_getTransactionCount", json!([from, "pending"]))?)?.to::<u64>();
    let gas_price = quantity(&rpc(rpc_url, "eth_gasPrice", json!([]))?)?.to::<u128>();
    let tip = 1_000_000u128;
    // The sender is the authority: its authorization takes the nonce after the transaction's.
    let auth = Authorization { chain_id: U256::from(chain_id), address: delegate, nonce: nonce + 1 };
    let sig = signer.sign_hash_sync(&auth.signature_hash())?;
    let signed = auth.into_signed(sig);
    let mut tx = TxEip7702 {
        chain_id,
        nonce,
        gas_limit: 500_000,
        max_fee_per_gas: gas_price * 2 + tip,
        max_priority_fee_per_gas: tip,
        to: from,
        value: U256::ZERO,
        access_list: Default::default(),
        authorization_list: vec![signed],
        input: data,
    };
    let sig = signer.sign_transaction_sync(&mut tx)?;
    let env: TxEnvelope = tx.into_signed(sig).into();
    let raw = hex::encode_prefixed(env.encoded_2718());
    let hash: B256 = serde_json::from_value(rpc(rpc_url, "eth_sendRawTransaction", json!([raw]))?)?;
    println!("sent {hash}; waiting for inclusion…");
    wait_receipt(rpc_url, hash)
}

/// Signs and sends a transaction; waits for its receipt. Returns the hash.
pub fn send_tx(
    rpc_url: &str,
    signer: &PrivateKeySigner,
    to: Address,
    value: U256,
    data: Bytes,
) -> Result<B256> {
    send_kind(rpc_url, signer, TxKind::Call(to), value, data)
}

/// Signs and sends a call (checked with `eth_estimateGas` first) without waiting for it to be
/// included; returns its hash.
pub fn send_tx_nowait(
    rpc_url: &str,
    signer: &PrivateKeySigner,
    to: Address,
    value: U256,
    data: Bytes,
) -> Result<B256> {
    let raw = sign_call(rpc_url, signer, TxKind::Call(to), value, data)?;
    Ok(serde_json::from_value(rpc(rpc_url, "eth_sendRawTransaction", json!([raw]))?)?)
}

/// Deploys `initcode`; returns the new contract's address.
pub fn deploy(rpc_url: &str, signer: &PrivateKeySigner, initcode: Bytes) -> Result<Address> {
    let hash = send_kind(rpc_url, signer, TxKind::Create, U256::ZERO, initcode)?;
    let r = rpc(rpc_url, "eth_getTransactionReceipt", json!([hash]))?;
    serde_json::from_value(r["contractAddress"].clone())
        .context("no contract address in the receipt")
}

fn send_kind(
    rpc_url: &str,
    signer: &PrivateKeySigner,
    to: TxKind,
    value: U256,
    data: Bytes,
) -> Result<B256> {
    let raw = sign_call(rpc_url, signer, to, value, data)?;
    let hash: B256 = serde_json::from_value(rpc(rpc_url, "eth_sendRawTransaction", json!([raw]))?)?;
    println!("sent {hash}; waiting for inclusion…");
    wait_receipt(rpc_url, hash)
}

/// Waits (up to 6 minutes) for a transaction to be included; fails if it reverted.
pub fn wait_receipt(rpc_url: &str, hash: B256) -> Result<B256> {
    for _ in 0..180 {
        let r = rpc(rpc_url, "eth_getTransactionReceipt", json!([hash]))?;
        if !r.is_null() {
            let ok = r["status"].as_str() == Some("0x1");
            let block = r["blockNumber"].as_str().unwrap_or("?");
            if !ok {
                bail!("transaction {hash} reverted in block {block}");
            }
            println!("included in block {block}");
            return Ok(hash);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    bail!("transaction {hash} not included after 6 minutes (still pending)")
}

/// A signed EIP-1559 transaction (gas from `eth_estimateGas`, so a call that would revert is
/// refused here), hex-encoded.
fn sign_call(
    rpc_url: &str,
    signer: &PrivateKeySigner,
    to: TxKind,
    value: U256,
    data: Bytes,
) -> Result<String> {
    let from = signer.address();
    let chain_id = quantity(&rpc(rpc_url, "eth_chainId", json!([]))?)?.to::<u64>();
    let nonce =
        quantity(&rpc(rpc_url, "eth_getTransactionCount", json!([from, "pending"]))?)?.to::<u64>();
    let gas_price = quantity(&rpc(rpc_url, "eth_gasPrice", json!([]))?)?.to::<u128>();
    let tip = quantity(&rpc(rpc_url, "eth_maxPriorityFeePerGas", json!([]))?)
        .map(|t| t.to::<u128>())
        .unwrap_or(1_000_000);
    let mut call = json!({"from": from, "value": format!("0x{value:x}"), "data": data});
    if let TxKind::Call(a) = to {
        call["to"] = json!(a);
    }
    let gas = quantity(&rpc(rpc_url, "eth_estimateGas", json!([call, "latest"]))?)?.to::<u64>();
    let mut tx = TxEip1559 {
        chain_id,
        nonce,
        // At most the per-transaction cap (EIP-7825).
        gas_limit: (gas + gas / 5).min(TX_GAS_CAP.max(gas)),
        max_fee_per_gas: gas_price * 2 + tip,
        max_priority_fee_per_gas: tip,
        to,
        value,
        input: data,
        ..Default::default()
    };
    let sig = signer.sign_transaction_sync(&mut tx)?;
    let env: TxEnvelope = tx.into_signed(sig).into();
    Ok(hex::encode_prefixed(env.encoded_2718()))
}

/// The chain's current epoch (ConsensusRegistry).
pub fn current_epoch(url: &str) -> Result<u64> {
    let data = bolt_system::abi::IConsensusRegistry::currentEpochCall {}.abi_encode();
    let out = rpc(
        url,
        "eth_call",
        json!([{"to": bolt_system::addresses::CONSENSUS, "data": hex::encode_prefixed(data)}, "latest"]),
    )?;
    Ok(quantity(&out)?.to::<u64>())
}

/// Runs a wallet command.
pub fn run(cmd: WalletCmd) -> Result<()> {
    match cmd {
        WalletCmd::New { out, plain } => {
            let s = PrivateKeySigner::random();
            write_wallet(&out, &s, !plain)?;
            println!("address {}", s.address());
            println!("saved to {} (keep it secret; back it up)", out.display());
        }
        WalletCmd::Encrypt { wallet, out } => {
            let raw: Value = serde_json::from_str(&std::fs::read_to_string(&wallet)?)?;
            if crate::keystore::is_encrypted(&raw) {
                bail!("{} is already encrypted", wallet.display());
            }
            let s = load_wallet(&wallet)?;
            write_wallet(&out, &s, true)?;
            println!("address {}", s.address());
            println!("encrypted to {}; delete {} once it works", out.display(), wallet.display());
        }
        WalletCmd::Balance { wallet, address, rpc: url } => {
            let a = match (wallet, address) {
                (Some(w), _) => load_wallet(&w)?.address(),
                (None, Some(a)) => a,
                (None, None) => bail!("give --wallet or --address"),
            };
            let b = quantity(&rpc(&url, "eth_getBalance", json!([a, "latest"]))?)?;
            println!("{a} {} BOLT", format_bolt(b));
        }
        WalletCmd::Send { wallet, to, value, data, rpc: url } => {
            let s = load_wallet(&wallet)?;
            send_tx(&url, &s, to, parse_bolt(&value)?, data.unwrap_or_default())?;
        }
        WalletCmd::Stake { wallet, key, amount, fee_recipient, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let k = keys::load_key(&key)?;
            let tx = keys::register_tx(&k, fee_recipient.unwrap_or(s.address()))?;
            let data: Bytes = tx["data"].as_str().context("data")?.parse()?;
            send_tx(&url, &s, bolt_system::addresses::STAKING, parse_bolt(&amount)?, data)?;
            println!(
                "validator {} registered; it joins committees once its stake matures",
                k.public_key()
            );
        }
        WalletCmd::SetPeer { wallet, key, node_key, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let k = keys::load_key(&key)?;
            let h = alloy_primitives::keccak256(k.public_key().as_slice());
            let call = bolt_system::abi::IStakingManager::idOfPubkeyCall { h }.abi_encode();
            let out = rpc(
                &url,
                "eth_call",
                json!([{"to": bolt_system::addresses::STAKING, "data": hex::encode_prefixed(call)}, "latest"]),
            )?;
            let id = quantity(&out)?.to::<u32>();
            if id == 0 {
                bail!("this BLS key is not registered yet (run `wallet stake` first)");
            }
            let peer = bolt_net::load_or_create_key(&node_key)?.public().to_peer_id();
            let tx = keys::set_peer_tx(id, &peer);
            let data: Bytes = tx["data"].as_str().context("data")?.parse()?;
            send_tx(&url, &s, bolt_system::addresses::SWARM, U256::ZERO, data)?;
            println!("validator {id} serves history from {peer}");
        }
        WalletCmd::DeployCertificates { wallet, rpc: url } => {
            let s = load_wallet(&wallet)?;
            let code = bolt_system::artifacts::certificates().bytecode.clone();
            let a = deploy(&url, &s, code)?;
            println!("Certificates deployed at {a}");
        }
        WalletCmd::StorageRegister { wallet, node_key, signed, rpc: url } => {
            use bolt_system::abi::ISwarmStorage;
            let s = load_wallet(&wallet)?;
            let peer = bolt_net::load_or_create_key(&node_key)?.public().to_peer_id();
            let peer_bytes = Bytes::copy_from_slice(&peer.to_bytes());
            let history = bolt_system::addresses::SWARM;
            if !signed {
                let data = ISwarmStorage::registerStorageCall { peerId: peer_bytes }.abi_encode();
                send_tx(&url, &s, history, U256::ZERO, data.into())?;
                println!("{} registered as a storage provider serving from {peer}", s.address());
                println!("run the node with --storage-account {}", s.address());
                return Ok(());
            }
            let deadline = U256::from(
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
                    + 86_400,
            );
            let call = ISwarmStorage::registrationDigestCall {
                account: s.address(),
                peerId: peer_bytes.clone(),
                deadline,
            }
            .abi_encode();
            let out = rpc(
                &url,
                "eth_call",
                json!([{"to": history, "data": hex::encode_prefixed(call)}, "latest"]),
            )?;
            let digest: B256 = out.as_str().context("digest")?.parse()?;
            let sig = alloy_signer::SignerSync::sign_hash_sync(&s, &digest)?;
            let data = ISwarmStorage::registerStorageForCall {
                account: s.address(),
                peerId: peer_bytes,
                deadline,
                sig: Bytes::from(sig.as_bytes().to_vec()),
            }
            .abi_encode();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "to": history,
                    "data": hex::encode_prefixed(data),
                    "account": s.address(),
                    "peerId": peer.to_string(),
                    "validForSeconds": 86_400,
                }))?
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolt_amounts() {
        assert_eq!(parse_bolt("64").unwrap(), U256::from(64u128 * WEI_PER_BOLT));
        assert_eq!(parse_bolt("0.5").unwrap(), U256::from(WEI_PER_BOLT / 2));
        assert_eq!(format_bolt(parse_bolt("1.25").unwrap()), "1.25");
        assert_eq!(format_bolt(U256::from(3u128 * WEI_PER_BOLT)), "3");
        assert!(parse_bolt("1.0000000000000000001").is_err());
    }
}
