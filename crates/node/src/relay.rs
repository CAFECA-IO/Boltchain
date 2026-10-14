//! Relay (`bolt_relay`): submits signed actions of accounts that hold no BOLT, paying the gas
//! from the node's relay account. Each accepted action pays the relay a fee out of the work it
//! enables (ADR 0011: a provider's registration, acceptance and receipt; settling a job past its
//! dispute window earns the job's relay fee; ADR 0013: an enclave's checkpoints).
//!
//! The relay only sends calls it recognises, paying at least `--relay-min-fee`, and only after
//! `eth_estimateGas` shows they would succeed, so a bad request costs it nothing.

use crate::wallet::{format_bolt, rpc, send_tx_nowait};
use alloy_primitives::{Address, B256, Bytes, U256, hex};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_system::{
    abi::{IComputeMarket, IEnclaveLease},
    addresses::{COMPUTE, LEASES},
};
use serde_json::json;

/// A relay sending from `signer` through the node's own JSON-RPC at `url`.
pub struct Relay {
    url: String,
    signer: PrivateKeySigner,
    min_fee: U256,
    /// One send at a time (nonces).
    lock: parking_lot::Mutex<()>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("account", &self.signer.address())
            .field("min_fee", &self.min_fee)
            .finish()
    }
}

impl Relay {
    /// A relay paying gas from `signer`, asking at least `min_fee` wei per action.
    pub fn new(url: String, signer: PrivateKeySigner, min_fee: U256) -> Self {
        Self { url, signer, min_fee, lock: parking_lot::Mutex::new(()) }
    }

    /// The relay's account.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    fn view<C: SolCall>(&self, to: Address, c: C) -> Result<C::Return, String> {
        let out = rpc(
            &self.url,
            "eth_call",
            json!([{"to": to, "data": hex::encode_prefixed(c.abi_encode())}, "latest"]),
        )
        .map_err(|e| format!("{e:#}"))?;
        let bytes: Bytes = serde_json::from_value(out).map_err(|e| e.to_string())?;
        C::abi_decode_returns(&bytes).map_err(|e| e.to_string())
    }

    fn fee_ok(&self, fee: U256, what: &str) -> Result<(), String> {
        if fee < self.min_fee {
            return Err(format!(
                "{what}: fee {} BOLT is below this relay's minimum of {} BOLT",
                format_bolt(fee),
                format_bolt(self.min_fee)
            ));
        }
        Ok(())
    }

    /// Whether this relay accepts `data` to `to` (without simulating it).
    pub fn check(&self, to: Address, data: &[u8]) -> Result<(), String> {
        let sel: [u8; 4] = data.get(..4).and_then(|s| s.try_into().ok()).ok_or("empty call")?;
        if to == COMPUTE {
            return match sel {
                IComputeMarket::registerForCall::SELECTOR => {
                    let c = IComputeMarket::registerForCall::abi_decode(data)
                        .map_err(|e| e.to_string())?;
                    self.fee_ok(c.fee, "registration")
                }
                IComputeMarket::acceptForCall::SELECTOR => {
                    let c = IComputeMarket::acceptForCall::abi_decode(data)
                        .map_err(|e| e.to_string())?;
                    self.fee_ok(U256::from(c.fee), "acceptance")
                }
                IComputeMarket::deliverForCall::SELECTOR => {
                    let c = IComputeMarket::deliverForCall::abi_decode(data)
                        .map_err(|e| e.to_string())?;
                    self.fee_ok(U256::from(c.fee), "receipt")
                }
                IComputeMarket::settleCall::SELECTOR => {
                    let c =
                        IComputeMarket::settleCall::abi_decode(data).map_err(|e| e.to_string())?;
                    let j = self.view(COMPUTE, IComputeMarket::jobCall { id: c.id })?;
                    self.fee_ok(U256::from(j.relayFee), "settlement")
                }
                IComputeMarket::payoutCall::SELECTOR => {
                    // Pushing a balance to its owner costs little; refuse empty ones.
                    let c =
                        IComputeMarket::payoutCall::abi_decode(data).map_err(|e| e.to_string())?;
                    let b =
                        self.view(COMPUTE, IComputeMarket::balanceOfCall { account: c.account })?;
                    if b.is_zero() { Err("nothing to pay out".into()) } else { Ok(()) }
                }
                _ => Err("this ComputeMarket call is not relayed".into()),
            };
        }
        if to == LEASES {
            return match sel {
                IEnclaveLease::checkpointCall::SELECTOR | IEnclaveLease::activateCall::SELECTOR => {
                    // Both pay the lease's relay fee to the sender.
                    let id = if sel == IEnclaveLease::checkpointCall::SELECTOR {
                        IEnclaveLease::checkpointCall::abi_decode(data).map_err(|e| e.to_string())?.id
                    } else {
                        IEnclaveLease::activateCall::abi_decode(data).map_err(|e| e.to_string())?.id
                    };
                    let l = self.view(LEASES, IEnclaveLease::leaseCall { id })?;
                    self.fee_ok(U256::from(l.relayFee), "checkpoint")
                }
                IEnclaveLease::payoutCall::SELECTOR => {
                    let c =
                        IEnclaveLease::payoutCall::abi_decode(data).map_err(|e| e.to_string())?;
                    let b =
                        self.view(LEASES, IEnclaveLease::balanceOfCall { account: c.account })?;
                    if b.is_zero() { Err("nothing to pay out".into()) } else { Ok(()) }
                }
                _ => Err("this EnclaveLease call is not relayed".into()),
            };
        }
        Err(format!("calls to {to} are not relayed"))
    }
}

impl bolt_rpc::CallRelay for Relay {
    fn relay(&self, to: Address, data: Vec<u8>) -> Result<B256, String> {
        self.check(to, &data)?;
        let _one = self.lock.lock();
        send_tx_nowait(&self.url, &self.signer, to, U256::ZERO, data.into())
            .map_err(|e| format!("{e:#}"))
    }
}

/// Sends `data` to `to` through the relay at `url` (`bolt_relay`); returns the transaction hash
/// and waits for it to be included.
pub fn through_relay(url: &str, to: Address, data: Vec<u8>) -> anyhow::Result<B256> {
    let hash: B256 =
        serde_json::from_value(rpc(url, "bolt_relay", json!([to, hex::encode_prefixed(&data)]))?)?;
    println!("relayed {hash}; waiting for inclusion…");
    crate::wallet::wait_receipt(url, hash)
}
