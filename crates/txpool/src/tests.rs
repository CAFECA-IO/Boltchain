use super::*;
use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
use alloy_network::TxSignerSync;
use alloy_primitives::{TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use std::collections::HashMap;

const CID: u64 = 1337;
const MIN_FEE: u64 = 10_000_000;

#[derive(Default)]
struct State(HashMap<Address, (u64, U256)>);
impl AccountState for State {
    fn nonce_balance(&self, a: &Address) -> (u64, U256) {
        self.0.get(a).copied().unwrap_or((0, U256::ZERO))
    }
}

fn pool() -> TxPool {
    TxPool::new(PoolConfig::new(CID, 30_000_000, MIN_FEE))
}

fn rich(signers: &[&PrivateKeySigner]) -> State {
    let mut s = State::default();
    for k in signers {
        s.0.insert(k.address(), (0, U256::from(10u128.pow(20))));
    }
    s
}

fn tx(k: &PrivateKeySigner, nonce: u64, tip: u128, max_fee: u128) -> TxEnvelope {
    let mut t = TxEip1559 {
        chain_id: CID,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        to: TxKind::Call(Address::repeat_byte(1)),
        value: U256::from(1),
        ..Default::default()
    };
    let sig = k.sign_transaction_sync(&mut t).unwrap();
    t.into_signed(sig).into()
}

#[test]
fn admission_rules() {
    let k = PrivateKeySigner::random();
    let st = rich(&[&k]);
    let p = pool();
    let fee = 10 * u128::from(MIN_FEE);
    p.add(tx(&k, 0, 1, fee), &st).unwrap();
    assert_eq!(p.add(tx(&k, 0, 1, fee), &st), Err(AddError::AlreadyKnown));
    // Replacement needs a 10% bump on both tip and fee cap.
    assert_eq!(p.add(tx(&k, 0, 1, fee + 1), &st), Err(AddError::Underpriced));
    p.add(tx(&k, 0, 2, fee * 2), &st).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(p.add(tx(&k, 0, 1, u128::from(MIN_FEE) - 1), &st), Err(AddError::FeeTooLow));
    assert_eq!(p.add(tx(&k, 16, 1, fee), &st), Err(AddError::NonceTooHigh));

    // Wrong chain id and unprotected legacy transactions.
    let mut wrong =
        TxEip1559 { chain_id: 8017, gas_limit: 21_000, max_fee_per_gas: fee, ..Default::default() };
    let sig = k.sign_transaction_sync(&mut wrong).unwrap();
    assert_eq!(p.add(wrong.into_signed(sig).into(), &st), Err(AddError::ChainId(8017)));
    let mut legacy =
        TxLegacy { chain_id: None, gas_limit: 21_000, gas_price: fee, ..Default::default() };
    let sig = k.sign_transaction_sync(&mut legacy).unwrap();
    assert_eq!(p.add(legacy.into_signed(sig).into(), &st), Err(AddError::Unprotected));

    // Poor sender.
    let poor = PrivateKeySigner::random();
    assert_eq!(p.add(tx(&poor, 0, 1, fee), &st), Err(AddError::InsufficientFunds));
    assert_eq!(p.add_raw(&[0xde, 0xad], &st), Err(AddError::Decode));
}

#[test]
fn best_orders_by_tip_and_respects_nonces() {
    let (a, b) = (PrivateKeySigner::random(), PrivateKeySigner::random());
    let st = rich(&[&a, &b]);
    let p = pool();
    let fee = 100 * u128::from(MIN_FEE);
    p.add(tx(&a, 0, 5, fee), &st).unwrap();
    p.add(tx(&a, 1, 50, fee), &st).unwrap();
    p.add(tx(&a, 3, 99, fee), &st).unwrap(); // gap: not executable
    p.add(tx(&b, 0, 20, fee), &st).unwrap();
    let best = p.best(MIN_FEE, &st);
    let order: Vec<(Address, u64)> = best.iter().map(|(t, s)| (*s, t.nonce())).collect();
    assert_eq!(order, vec![(b.address(), 0), (a.address(), 0), (a.address(), 1)]);
    assert_eq!(p.pending_nonce(&a.address(), 0), 2);

    // After a block includes a:0 and b:0, those drop out.
    let mut st2 = rich(&[&a, &b]);
    st2.0.get_mut(&a.address()).unwrap().0 = 1;
    st2.0.get_mut(&b.address()).unwrap().0 = 1;
    p.on_new_block(&st2);
    assert_eq!(p.len(), 2);
}

#[test]
fn fee_cap_below_base_fee_waits() {
    let a = PrivateKeySigner::random();
    let st = rich(&[&a]);
    let p = pool();
    p.add(tx(&a, 0, 1, 2 * u128::from(MIN_FEE)), &st).unwrap();
    assert_eq!(p.best(MIN_FEE, &st).len(), 1);
    assert!(p.best(3 * MIN_FEE, &st).is_empty());
}

#[test]
fn calldata_floor_and_intrinsic_gas_are_checked_at_admission() {
    let k = PrivateKeySigner::random();
    let st = rich(&[&k]);
    let p = pool();
    let fee = 10 * u128::from(MIN_FEE);
    let with = |gas_limit: u64, input: Vec<u8>, to: TxKind| {
        let mut t = TxEip1559 {
            chain_id: 1337,
            gas_limit,
            max_fee_per_gas: fee,
            to,
            input: input.into(),
            ..Default::default()
        };
        let sig = k.sign_transaction_sync(&mut t).unwrap();
        TxEnvelope::from(t.into_signed(sig))
    };
    let call = TxKind::Call(Address::repeat_byte(1));
    // 2,000 non-zero bytes: intrinsic 21,000 + 32,000 = 53,000, but the EIP-7623 floor is
    // 21,000 + 10 * 8,000 = 101,000.
    let data = vec![0xab; 2000];
    assert_eq!(p.add(with(60_000, data.clone(), call), &st), Err(AddError::IntrinsicGas(101_000)));
    p.add(with(101_000, data, call), &st).unwrap();
    // Contract creation: 53,000 plus calldata and initcode words.
    let code = vec![0u8; 64];
    assert!(matches!(
        p.add(with(53_000, code.clone(), TxKind::Create), &st),
        Err(AddError::IntrinsicGas(n)) if n > 53_000
    ));
}

#[test]
fn stuck_transactions_are_evicted_so_the_sender_can_continue() {
    let k = PrivateKeySigner::random();
    let p = pool();
    let mut st = rich(&[&k]);
    let fee = 2 * MIN_FEE as u128;
    // 16 queued behind a head transaction that never executes: the next nonce is refused
    for n in 0..16 {
        p.add(tx(&k, n, 1, fee), &st).unwrap();
    }
    assert_eq!(p.add(tx(&k, 16, 1, fee), &st), Err(AddError::NonceTooHigh));
    assert_eq!(p.pending_nonce(&k.address(), 0), 16);

    // too old: everything goes, and the pending nonce is the account nonce again
    p.evict(&st, Instant::now() + p.cfg.max_age + Duration::from_secs(1));
    assert!(p.is_empty());
    assert_eq!(p.pending_nonce(&k.address(), 0), 0);

    // the next transaction is no longer affordable: it goes, later ones wait behind the gap
    for n in 0..3 {
        p.add(tx(&k, n, 1, fee), &st).unwrap();
    }
    st.0.insert(k.address(), (0, U256::from(1)));
    p.on_new_block(&st);
    assert_eq!(p.len(), 2);
    assert_eq!(p.pending_nonce(&k.address(), 0), 0, "the sender can resend nonce 0");
    assert!(p.best(MIN_FEE, &st).is_empty());
}
