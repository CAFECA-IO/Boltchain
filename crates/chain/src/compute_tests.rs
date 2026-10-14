//! ComputeMarket on a running chain (ADR 0011): a job is posted, taken, delivered and disputed
//! with ordinary transactions; the first block of the next epoch hands the dispute to a verifier
//! panel drawn from the committee.

use super::*;
use crate::epoch_tests::{bolt, call_tx, genesis, produce, signer, view};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use bolt_system::{abi::*, addresses::*};

#[test]
fn disputes_reach_a_panel_at_the_next_epoch() {
    let g = genesis();
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain::open(dir.path(), &g).unwrap();
    let requester = signer();
    // Second funded dev account as the provider.
    let provider: PrivateKeySigner =
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".parse().unwrap();
    produce(&chain, vec![]);
    let reg = IComputeMarket::registerCall {
        encKey: B256::repeat_byte(1),
        peerId: Bytes::from_static(b"p"),
    };
    produce(&chain, vec![call_tx(&provider, 0, COMPUTE, U256::ZERO, reg.abi_encode())]);
    let now = chain.head().unwrap().timestamp;
    let post = IComputeMarket::postCall {
        provider_: provider.address(),
        model: 1,
        input: Bytes::from_static(b"in"),
        priceIn: 10u128.pow(18),
        priceOut: 10u128.pow(18),
        maxIn: 1000,
        maxOut: 1000,
        deadline: now + 3600,
        window: 600,
        relayFee: 0,
    };
    let model = IModelRegistry::registerCall {
        name: "m".into(),
        weights: Bytes::from_static(b"w"),
        tokenizer: Bytes::new(),
        runtime: "r".into(),
        parameters: 1,
        vramMiB: 1,
    };
    produce(&chain, vec![call_tx(&requester, 0, MODELS, U256::ZERO, model.abi_encode())]);
    produce(&chain, vec![call_tx(&requester, 1, COMPUTE, bolt(2), post.abi_encode())]);
    let id = U256::ZERO;
    let accept = IComputeMarket::acceptCall { id };
    let deliver = IComputeMarket::deliverCall {
        id,
        output: Bytes::from_static(b"out"),
        tokensIn: 10,
        tokensOut: 20,
    };
    produce(&chain, vec![call_tx(&provider, 1, COMPUTE, U256::ZERO, accept.abi_encode())]);
    produce(&chain, vec![call_tx(&provider, 2, COMPUTE, U256::ZERO, deliver.abi_encode())]);
    let dispute = IComputeMarket::disputeCall { id, reason: Bytes::new() };
    produce(&chain, vec![call_tx(&requester, 2, COMPUTE, bolt(1), dispute.abi_encode())]);
    assert_eq!(view(&chain, COMPUTE, IComputeMarket::pendingDisputesCall {}), vec![id]);

    // Up to the first block of the next epoch.
    let head = chain.head().unwrap().number;
    let next_start = (chain.rules().epoch_of(head) + 1) * chain.rules().epoch_slots + 1;
    while chain.head().unwrap().number < next_start {
        produce(&chain, vec![]);
    }
    let epoch = chain.rules().epoch_of(next_start);
    assert!(view(&chain, COMPUTE, IComputeMarket::pendingDisputesCall {}).is_empty());
    let panel = view(&chain, COMPUTE, IComputeMarket::panelCall { epoch });
    assert!(!panel.is_empty(), "panel drawn from the committee");
    let committee = view(&chain, CONSENSUS, IConsensusRegistry::committeeCall { epoch });
    assert!(panel.iter().all(|m| committee.ids.contains(m)));
}
