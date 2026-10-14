//! End-to-end: a wallet-style client talks to the node over HTTP JSON-RPC.
//! This is the automated stand-in for the M1 acceptance check with Foundry and MetaMask.

use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, U256, address};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::{Filter, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use bolt_chain::Chain;
use bolt_primitives::Genesis;
use bolt_rpc::RpcContext;
use bolt_txpool::{PoolConfig, TxPool};
use boltchain::devnet::produce;
use std::sync::Arc;

const DEV_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Runtime of a small contract:
///   with calldata: SSTORE(0, calldata[0..32]) and LOG1(topic 0xbeef, data = calldata[0..32])
///   without calldata: return SLOAD(0)
fn runtime() -> Vec<u8> {
    vec![
        0x36, 0x15, 0x60, 0x14,
        0x57, // CALLDATASIZE ISZERO PUSH1 0x14 JUMPI (JUMPDEST at offset 20)
        0x5f, 0x35, 0x80, 0x5f, 0x55, // PUSH0 CALLDATALOAD DUP1 PUSH0 SSTORE
        0x5f, 0x52, // PUSH0 MSTORE
        0x61, 0xbe, 0xef, 0x60, 0x20, 0x5f, 0xa1, // PUSH2 beef PUSH1 20 PUSH0 LOG1
        0x00, // STOP
        0x5b, 0x5f, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f,
        0xf3, // JUMPDEST PUSH0 SLOAD PUSH0 MSTORE PUSH1 20 PUSH0 RETURN
    ]
}

fn initcode() -> Bytes {
    let rt = runtime();
    let n = rt.len() as u8;
    // PUSH1 n PUSH1 12 PUSH0 CODECOPY PUSH1 n PUSH0 RETURN  (11 bytes) + pad to 12
    let mut code = vec![0x60, n, 0x60, 0x0c, 0x5f, 0x39, 0x60, n, 0x5f, 0xf3, 0x00, 0x00];
    code.extend(rt);
    code.into()
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_flow_over_json_rpc() {
    let genesis = Genesis::from_json(include_str!("../../../genesis/dev.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let chain = Arc::new(Chain::open(dir.path(), &genesis).unwrap());
    let cfg = chain.config().clone();
    let pool =
        Arc::new(TxPool::new(PoolConfig::new(cfg.chain_id, cfg.gas_limit, cfg.min_base_fee_wei)));
    let ctx = RpcContext {
        chain: chain.clone(),
        pool: pool.clone(),
        client_version: "test".into(),
        host: None,
        relay: None,
        forwarder: None,
    };
    let (addr, _handle) = bolt_rpc::start("127.0.0.1:0".parse().unwrap(), ctx).await.unwrap();
    let url = format!("http://{addr}").parse().unwrap();

    let signer: PrivateKeySigner = DEV_KEY.parse().unwrap();
    let me = signer.address();
    let provider = ProviderBuilder::new().wallet(EthereumWallet::from(signer)).connect_http(url);

    let mine = || {
        let (c, p) = (chain.clone(), pool.clone());
        async move {
            tokio::task::spawn_blocking(move || produce(&c, &p, Address::repeat_byte(0xbe)))
                .await
                .unwrap()
                .unwrap()
        }
    };

    // Basic chain info.
    assert_eq!(provider.get_chain_id().await.unwrap(), 1337);
    assert_eq!(provider.get_block_number().await.unwrap(), 0);
    let start_balance = provider.get_balance(me).await.unwrap();
    assert_eq!(start_balance, U256::from(10_000u128 * 10u128.pow(18)));

    // 1. Transfer (the provider fills nonce, gas and EIP-1559 fees through RPC).
    let bob = address!("00000000000000000000000000000000000b0b00");
    let pending = provider
        .send_transaction(TransactionRequest::default().with_to(bob).with_value(U256::from(12345)))
        .await
        .unwrap();
    mine().await;
    let receipt = pending.get_receipt().await.unwrap();
    assert!(receipt.status());
    assert_eq!(receipt.gas_used, 21_000);
    assert_eq!(provider.get_balance(bob).await.unwrap(), U256::from(12345));

    // 2. Deploy a contract; gas is estimated over RPC.
    let pending = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(initcode()))
        .await
        .unwrap();
    mine().await;
    let receipt = pending.get_receipt().await.unwrap();
    assert!(receipt.status());
    let contract = receipt.contract_address.expect("contract address");
    assert_eq!(provider.get_code_at(contract).await.unwrap(), Bytes::from(runtime()));

    // 3. Call it: stores a value and emits a log.
    let value = U256::from(0xc0ffee);
    let pending = provider
        .send_transaction(
            TransactionRequest::default()
                .with_to(contract)
                .with_input(Bytes::from(value.to_be_bytes::<32>().to_vec())),
        )
        .await
        .unwrap();
    mine().await;
    let receipt = pending.get_receipt().await.unwrap();
    assert!(receipt.status());
    assert_eq!(receipt.inner.logs().len(), 1);

    // eth_call reads it back; eth_getStorageAt agrees.
    let out = provider.call(TransactionRequest::default().with_to(contract)).await.unwrap();
    assert_eq!(U256::from_be_slice(&out), value);
    assert_eq!(provider.get_storage_at(contract, U256::ZERO).await.unwrap(), value);

    // eth_getProof: account and slot 0 verify against the head block's stateRoot.
    let proof = provider.get_proof(contract, vec![alloy_primitives::B256::ZERO]).await.unwrap();
    let head =
        provider.get_block_by_number(alloy_eips::BlockNumberOrTag::Latest).await.unwrap().unwrap();
    let acct = alloy_trie::TrieAccount {
        nonce: proof.nonce,
        balance: proof.balance,
        storage_root: proof.storage_hash,
        code_hash: proof.code_hash,
    };
    alloy_trie::proof::verify_proof(
        head.header.state_root,
        alloy_trie::Nibbles::unpack(alloy_primitives::keccak256(contract)),
        Some(alloy_rlp::encode(acct)),
        &proof.account_proof,
    )
    .unwrap();
    assert_eq!(proof.storage_proof[0].value, value);
    alloy_trie::proof::verify_proof(
        proof.storage_hash,
        alloy_trie::Nibbles::unpack(alloy_primitives::keccak256(alloy_primitives::B256::ZERO)),
        Some(alloy_rlp::encode(value)),
        &proof.storage_proof[0].proof,
    )
    .unwrap();
    // Only the latest state has proofs.
    assert!(provider.get_proof(contract, vec![]).block_id(1.into()).await.is_err());

    // eth_getLogs finds the event.
    let logs = provider.get_logs(&Filter::new().address(contract).from_block(0)).await.unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(U256::from_be_slice(logs[0].data().data.as_ref()), value);

    // Historical state: bob's balance before the transfer block was zero.
    let bal_at_0 = provider.get_balance(bob).block_id(0.into()).await.unwrap();
    assert_eq!(bal_at_0, U256::ZERO);

    // Blocks by number with full transactions.
    let b1 = provider.get_block_by_number(1.into()).full().await.unwrap().unwrap();
    assert_eq!(b1.transactions.len(), 1);
    assert_eq!(provider.get_block_number().await.unwrap(), 3);

    // Blob transactions are refused at the door.
    let err = provider.raw_request::<_, serde_json::Value>("eth_blobBaseFee".into(), ()).await;
    assert!(err.is_err());

    // The sender paid fees: balance dropped by more than the value sent.
    let end = provider.get_balance(me).await.unwrap();
    assert!(end < start_balance - U256::from(12345));
}
