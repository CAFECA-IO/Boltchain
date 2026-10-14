//! TEE leasing (ADR 0013): Intel's real collateral accepted under the Intel root; simulated
//! TDX quotes verified on chain exactly as `bolt-attest` verifies them; a lease from machine
//! registration through activation, hourly checkpoints, rollback refusal, migration,
//! degradation, equivocation slashing; T2 machines through the verifier panel; the limited
//! wallet driven by the active enclave key.

use crate::{abi::*, addresses::*, tests::Evm};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use bolt_attest::{
    Collateral,
    sim::{SimIntel, SimPlatform},
    tdx::{self, TdReport},
    tpm,
    tpm_sim::{SimTpmCa, SoftTpm},
};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../attest/fixtures/intel/");
/// 2026-10-15: inside the fixtures' validity.
const NOW: u64 = 1_792_022_400;
/// 2027-01-01.
const LATER: u64 = 1_798_761_600;

fn bolt(n: u64) -> U256 {
    U256::from(n) * U256::from(10u64).pow(U256::from(18))
}

fn fixture(name: &str) -> Bytes {
    std::fs::read(format!("{FIX}{name}")).unwrap().into()
}

fn genesis_dev() -> bolt_primitives::Genesis {
    crate::tests::dev_genesis()
}

#[test]
fn dev_genesis_trusts_the_simulated_root() {
    let g = genesis_dev();
    let (x, y) = SimIntel::dev().root_point();
    assert_eq!(g.dev_tee_root, Some([B256::from(x), B256::from(y)]));
    let mut evm = Evm::from_genesis(&g);
    let r = evm.view(COLLATERAL, ITeeCollateral::rootCall {});
    assert_eq!((r.x, r.y), (B256::from(x), B256::from(y)));
}

#[test]
fn intel_collateral_is_accepted_on_chain() {
    let mut g = genesis_dev();
    g.dev_tee_root = None;
    let mut evm = Evm::from_genesis(&g);
    evm.timestamp = NOW;
    let anyone = Address::repeat_byte(0x77);
    evm.fund(anyone, bolt(10));
    let mut gas = Vec::new();
    let mut run = |evm: &mut Evm, what: &str, data: Vec<u8>| {
        let (ok, out, used) = evm.tx_gas(anyone, COLLATERAL, U256::ZERO, data);
        assert!(ok, "{what} reverted: {out}");
        gas.push((what.to_string(), used));
    };
    run(
        &mut evm,
        "root CRL",
        ITeeCollateral::setCrlCall { der: fixture("root-ca-crl.der") }.abi_encode(),
    );
    for ca in ["pck-platform-ca.der", "pck-processor-ca.der", "tcb-signing.der"] {
        run(&mut evm, ca, ITeeCollateral::addCaCall { der: fixture(ca) }.abi_encode());
    }
    for crl in ["pck-crl-platform.der", "pck-crl-processor.der"] {
        run(&mut evm, crl, ITeeCollateral::setCrlCall { der: fixture(crl) }.abi_encode());
    }
    // The signer is named by its subject hash, as bolt-attest reports it.
    let mut c = Collateral::intel();
    let signer = c.add_ca(&fixture("tcb-signing.der"), NOW).unwrap();
    run(
        &mut evm,
        "TCB info",
        ITeeCollateral::setTcbInfoCall { document: fixture("tcb-info-00806f050000.json"), signer }
            .abi_encode(),
    );
    run(
        &mut evm,
        "QE identity",
        ITeeCollateral::setQeIdentityCall { document: fixture("qe-identity.json"), signer }
            .abi_encode(),
    );
    for (what, used) in &gas {
        println!("{what}: {used} gas");
    }
    let info = evm.view(
        COLLATERAL,
        ITeeCollateral::tcbInfoCall {
            fmspc: alloy_primitives::FixedBytes([0, 0x80, 0x6f, 5, 0, 0]),
        },
    );
    assert_eq!(info.info.evaluation, 20);
    assert_eq!(info.levels.len(), 6);
    assert_eq!(evm.view(COLLATERAL, ITeeCollateral::qeIdentityCall {}).isvprodid, 2);
    // Replaying an older (equal) document is refused; so is a tampered one.
    assert!(!evm.try_call(
        anyone,
        COLLATERAL,
        U256::ZERO,
        ITeeCollateral::setTcbInfoCall { document: fixture("tcb-info-00806f050000.json"), signer },
    ));
    let bad = String::from_utf8(fixture("qe-identity.json").to_vec())
        .unwrap()
        .replace("\"tcbEvaluationDataNumber\":20", "\"tcbEvaluationDataNumber\":21");
    assert!(!evm.try_call(
        anyone,
        COLLATERAL,
        U256::ZERO,
        ITeeCollateral::setQeIdentityCall { document: bad.into_bytes().into(), signer },
    ));
}

use alloy_sol_types::SolCall;

/// A dev chain with the simulated collateral submitted, and actors.
struct Tee {
    evm: Evm,
    sim: SimIntel,
    col: Collateral,
    operator: Address,
    renter: Address,
    relayer: Address,
    image: u64,
}

const AGENT: B256 = B256::repeat_byte(0xa9);
const MR_TD: [u8; 48] = [7; 48];
const RTMR: [[u8; 48]; 4] = [[1; 48], [2; 48], [3; 48], [0; 48]];

fn tee() -> Tee {
    let sim = SimIntel::dev();
    let mut evm = Evm::from_genesis(&genesis_dev());
    evm.timestamp = LATER;
    let (operator, renter, relayer) =
        (Address::repeat_byte(0x01), Address::repeat_byte(0x02), Address::repeat_byte(0x03));
    for a in [operator, renter, relayer] {
        evm.fund(a, bolt(1000));
    }
    let mut col = Collateral::with_root(sim.root_point());
    let c = sim.collateral();
    let mut signer = B256::ZERO;
    for ca in &c.cas {
        evm.call(
            relayer,
            COLLATERAL,
            U256::ZERO,
            ITeeCollateral::addCaCall { der: ca.clone().into() },
        );
        signer = col.add_ca(ca, LATER).unwrap();
    }
    for crl in &c.crls {
        evm.call(
            relayer,
            COLLATERAL,
            U256::ZERO,
            ITeeCollateral::setCrlCall { der: crl.clone().into() },
        );
        col.add_crl(crl).unwrap();
    }
    evm.call(
        relayer,
        COLLATERAL,
        U256::ZERO,
        ITeeCollateral::setTcbInfoCall { document: c.tcb_info.clone().into_bytes().into(), signer },
    );
    col.set_tcb_info(&c.tcb_info, LATER).unwrap();
    evm.call(
        relayer,
        COLLATERAL,
        U256::ZERO,
        ITeeCollateral::setQeIdentityCall {
            document: c.qe_identity.clone().into_bytes().into(),
            signer,
        },
    );
    col.set_qe_identity(&c.qe_identity, LATER).unwrap();
    // The runtime image and its TDX measurement.
    let image = evm.call(
        renter,
        IMAGES,
        U256::ZERO,
        IImageRegistry::registerCall {
            name: "bolt-art".into(),
            source: Bytes::from_static(b"bafy-source"),
            build: "nix build .#bolt-art".into(),
        },
    );
    evm.call(
        renter,
        IMAGES,
        U256::ZERO,
        IImageRegistry::addMeasurementCall {
            id: image,
            kind: 1,
            raw: TdReport::measurement_bytes(&MR_TD, &RTMR[..3]).into(),
            platform: "simulated TDX".into(),
        },
    );
    Tee { evm, sim, col, operator, renter, relayer, image }
}

impl Tee {
    fn quote(&self, machine: &SimPlatform, binding: B256, second: B256) -> Bytes {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(binding.as_slice());
        rd[32..].copy_from_slice(second.as_slice());
        machine.quote(&SimPlatform::td_report(MR_TD, RTMR, rd)).into()
    }

    fn register(&mut self, operator: Address, machine: &SimPlatform) -> u64 {
        let binding = self.evm.view(LEASES, IEnclaveLease::machineBindingCall { operator });
        let q = self.quote(machine, binding, B256::ZERO);
        let (ok, out, gas) = self.evm.tx_gas(
            operator,
            LEASES,
            U256::ZERO,
            IEnclaveLease::registerMachineCall {
                kind: 1,
                attestation: q,
                endpoint: "https://tee.example:8545".into(),
                cpus: 16,
                memGiB: 64,
                gpu: String::new(),
            }
            .abi_encode(),
        );
        assert!(ok, "registerMachine reverted: {out}");
        println!("registerMachine (TDX quote verified on chain): {gas} gas");
        let m = IEnclaveLease::registerMachineCall::abi_decode_returns(&out).unwrap();
        self.evm.call(
            operator,
            LEASES,
            U256::ZERO,
            IEnclaveLease::setOfferCall { m, pricePerHour: bolt(1).to::<u128>(), available: true },
        );
        m
    }

    fn lease(&mut self, m: u64, escrow: U256) -> U256 {
        self.evm.call(
            self.renter,
            LEASES,
            escrow,
            IEnclaveLease::createLeaseCall {
                m,
                image: self.image,
                agentHash: AGENT,
                minTcb: 1,
                minBond: 0,
                relayFee: (bolt(1) / U256::from(100)).to::<u128>(),
            },
        )
    }

    fn activate(&mut self, id: U256, machine: &SimPlatform, enclave: &PrivateKeySigner) -> bool {
        let enc = B256::repeat_byte(0xee);
        let binding = self.evm.view(
            LEASES,
            IEnclaveLease::enclaveBindingCall { id, signer: enclave.address(), encKey: enc },
        );
        let q = self.quote(machine, binding, AGENT);
        let (ok, _, gas) = self.evm.tx_gas(
            self.relayer,
            LEASES,
            U256::ZERO,
            IEnclaveLease::activateCall {
                id,
                signer: enclave.address(),
                encKey: enc,
                attestation: q,
            }
            .abi_encode(),
        );
        if ok {
            println!("activate: {gas} gas");
        }
        ok
    }

    fn signed(
        &mut self,
        id: U256,
        enclave: &PrivateKeySigner,
        version: u64,
        root: B256,
    ) -> IEnclaveLease::Signed {
        let cid = Bytes::from(format!("bafy-state-{version}-{root}").into_bytes());
        let seen = keccak256(b"0");
        let digest = self.evm.view(
            LEASES,
            IEnclaveLease::checkpointDigestCall {
                id,
                version,
                stateRoot: root,
                cidHash: keccak256(&cid),
                seenBlockhash: seen,
            },
        );
        let sig = enclave.sign_hash_sync(&digest).unwrap();
        IEnclaveLease::Signed {
            stateRoot: root,
            cidHash: keccak256(&cid),
            seenBlockhash: seen,
            sig: sig.as_bytes().to_vec().into(),
        }
    }

    fn checkpoint(
        &mut self,
        id: U256,
        enclave: &PrivateKeySigner,
        version: u64,
        root: B256,
    ) -> bool {
        let s = self.signed(id, enclave, version, root);
        let cid = Bytes::from(format!("bafy-state-{version}-{root}").into_bytes());
        self.evm.try_call(
            self.relayer,
            LEASES,
            U256::ZERO,
            IEnclaveLease::checkpointCall {
                id,
                version,
                stateCid: cid,
                stateRoot: root,
                seenBlock: U256::ZERO,
                sig: s.sig,
            },
        )
    }

    fn lease_view(&mut self, id: U256) -> IEnclaveLease::Lease {
        self.evm.view(LEASES, IEnclaveLease::leaseCall { id })
    }
}

#[test]
fn simulated_quote_verifies_on_chain_as_off_chain() {
    let t = tee();
    let m = t.sim.platform(1);
    let mut t = t;
    let q = t.quote(&m, B256::repeat_byte(5), AGENT);
    let relayer = t.relayer;
    let on = t.evm.call(relayer, TDX, U256::ZERO, ITdxVerifier::verifyCall { quote: q.clone() });
    let off = tdx::verify(&q, &t.col, LATER).unwrap();
    assert_eq!(on.machineId, off.machine_id);
    assert_eq!(on.tcbStatus, off.tcb_status);
    assert_eq!(on.qeStatus, off.qe_status);
    assert_eq!(on.pckSerial, off.pck_serial);
    assert_eq!(on.pckIssuer, off.pck_issuer);
    assert_eq!(on.reportData.as_ref(), &off.report.report_data[..]);
    assert_eq!(
        t.evm.view(TDX, ITdxVerifier::measurementOfCall { r: on }),
        off.report.measurement()
    );
    let mut bad = q.to_vec();
    bad[tdx::HEADER + 136] ^= 1; // MRTD
    assert!(!t.evm.try_call(
        relayer,
        TDX,
        U256::ZERO,
        ITdxVerifier::verifyCall { quote: bad.into() }
    ));
}

#[test]
fn a_lease_runs_checkpoints_and_pays_by_the_hour() {
    let mut t = tee();
    let m1 = t.sim.platform(1);
    let operator = t.operator;
    let machine = t.register(operator, &m1);
    // One machine, one operator.
    let other = Address::repeat_byte(0x09);
    t.evm.fund(other, bolt(10));
    let binding = t.evm.view(LEASES, IEnclaveLease::machineBindingCall { operator: other });
    let q = t.quote(&m1, binding, B256::ZERO);
    assert!(!t.evm.try_call(
        other,
        LEASES,
        U256::ZERO,
        IEnclaveLease::registerMachineCall {
            kind: 1,
            attestation: q,
            endpoint: "x".into(),
            cpus: 1,
            memGiB: 1,
            gpu: String::new()
        },
    ));

    let id = t.lease(machine, bolt(10));
    let enclave = PrivateKeySigner::random();
    // A quote bound to another key, or for another agent package, does not activate it.
    let enc = B256::repeat_byte(0xee);
    let wrong = t.evm.view(
        LEASES,
        IEnclaveLease::enclaveBindingCall { id, signer: Address::repeat_byte(5), encKey: enc },
    );
    let q = t.quote(&m1, wrong, AGENT);
    assert!(!t.evm.try_call(
        t.relayer,
        LEASES,
        U256::ZERO,
        IEnclaveLease::activateCall { id, signer: enclave.address(), encKey: enc, attestation: q },
    ));
    let relayer_before = t.evm.view(LEASES, IEnclaveLease::balanceOfCall { account: t.relayer });
    assert!(t.activate(id, &m1, &enclave));
    assert_eq!(t.evm.view(LEASES, IEnclaveLease::activeSignerCall { id }), enclave.address());
    let relayer_after = t.evm.view(LEASES, IEnclaveLease::balanceOfCall { account: t.relayer });
    assert_eq!(relayer_after - relayer_before, bolt(1) / U256::from(100));

    // Within the hour: recorded, not paid. After an hour: one hour paid, 20% into the bond.
    assert!(t.checkpoint(id, &enclave, 1, B256::repeat_byte(1)));
    assert_eq!(t.lease_view(id).hoursPaid, 0);
    t.evm.timestamp += 3600;
    assert!(t.checkpoint(id, &enclave, 2, B256::repeat_byte(2)));
    let l = t.lease_view(id);
    assert_eq!(l.hoursPaid, 1);
    assert_eq!(l.version, 2);
    let paid = t.evm.view(LEASES, IEnclaveLease::balanceOfCall { account: operator });
    assert_eq!(paid, bolt(1) * U256::from(8) / U256::from(10));
    assert_eq!(
        t.evm.view(LEASES, IEnclaveLease::operatorsCall { operator }).bond,
        bolt(1) / U256::from(5)
    );

    // Rollback: an older or equal version is refused; another key's checkpoint too.
    assert!(!t.checkpoint(id, &enclave, 2, B256::repeat_byte(3)));
    assert!(!t.checkpoint(id, &enclave, 1, B256::repeat_byte(3)));
    assert!(!t.checkpoint(id, &PrivateKeySigner::random(), 3, B256::repeat_byte(3)));

    // The renter ends it; the rest of the escrow comes back.
    let renter = t.renter;
    assert!(t.evm.try_call(renter, LEASES, U256::ZERO, IEnclaveLease::terminateCall { id }));
    let back = t.evm.view(LEASES, IEnclaveLease::balanceOfCall { account: renter });
    // 10 BOLT - 1 hour - 3 relay fees (activation, two checkpoints).
    assert_eq!(back, bolt(10) - bolt(1) - bolt(3) / U256::from(100));
    assert_eq!(t.evm.view(LEASES, IEnclaveLease::activeSignerCall { id }), Address::ZERO);
}

#[test]
fn migration_replaces_the_enclave_and_keeps_the_version() {
    let mut t = tee();
    let (m1, m2) = (t.sim.platform(1), t.sim.platform(2));
    let operator = t.operator;
    let a = t.register(operator, &m1);
    let op2 = Address::repeat_byte(0x04);
    t.evm.fund(op2, bolt(10));
    let b = t.register(op2, &m2);
    let id = t.lease(a, bolt(10));
    let old = PrivateKeySigner::random();
    assert!(t.activate(id, &m1, &old));
    assert!(t.checkpoint(id, &old, 5, B256::repeat_byte(5)));
    let renter = t.renter;
    // Not while the operator is healthy…
    assert!(!t.evm.try_call(renter, LEASES, U256::ZERO, IEnclaveLease::migrateCall { id, to: b }));
    // …but after two hours of silence.
    t.evm.timestamp += 2 * 3600;
    assert!(t.evm.try_call(renter, LEASES, U256::ZERO, IEnclaveLease::migrateCall { id, to: b }));
    assert!(!t.checkpoint(id, &old, 6, B256::repeat_byte(6)));
    // The old machine's quote cannot activate it on the new one.
    let new = PrivateKeySigner::random();
    assert!(!t.activate(id, &m1, &new));
    assert!(t.activate(id, &m2, &new));
    // The version carries over: the new enclave cannot go back.
    assert!(!t.checkpoint(id, &new, 5, B256::repeat_byte(7)));
    assert!(t.checkpoint(id, &new, 6, B256::repeat_byte(7)));
    // The old key stays dead.
    assert!(!t.checkpoint(id, &old, 7, B256::repeat_byte(8)));
}

#[test]
fn equivocation_slashes_the_whole_bond_and_blacklists_the_machine() {
    let mut t = tee();
    let m1 = t.sim.platform(1);
    let operator = t.operator;
    let machine = t.register(operator, &m1);
    t.evm.call(operator, LEASES, bolt(64), IEnclaveLease::depositBondCall {});
    let id = t.lease(machine, bolt(10));
    let enclave = PrivateKeySigner::random();
    assert!(t.activate(id, &m1, &enclave));
    assert!(t.checkpoint(id, &enclave, 1, B256::repeat_byte(1)));
    // Two states for version 2 (one could be an intermediate checkpoint, never on chain).
    let a = t.signed(id, &enclave, 2, B256::repeat_byte(2));
    let b = t.signed(id, &enclave, 2, B256::repeat_byte(3));
    let reporter = Address::repeat_byte(0x55);
    t.evm.fund(reporter, bolt(1));
    // The same state twice is no evidence.
    assert!(!t.evm.try_call(
        reporter,
        LEASES,
        U256::ZERO,
        IEnclaveLease::reportEquivocationCall { id, version: 2, a: a.clone(), b: a.clone() },
    ));
    t.evm.call(
        reporter,
        LEASES,
        U256::ZERO,
        IEnclaveLease::reportEquivocationCall { id, version: 2, a, b },
    );
    assert_eq!(t.evm.view(LEASES, IEnclaveLease::balanceOfCall { account: reporter }), bolt(32));
    assert_eq!(t.evm.view(LEASES, IEnclaveLease::burnedCall {}), bolt(32));
    assert_eq!(t.evm.view(LEASES, IEnclaveLease::operatorsCall { operator }).bond, U256::ZERO);
    assert!(t.evm.view(LEASES, IEnclaveLease::blacklistedCall { machineId: m1.machine_id() }));
    assert_eq!(t.lease_view(id).state, 4);
    // The machine cannot come back, under any operator.
    let binding = t.evm.view(LEASES, IEnclaveLease::machineBindingCall { operator });
    let q = t.quote(&m1, binding, B256::ZERO);
    assert!(!t.evm.try_call(
        operator,
        LEASES,
        U256::ZERO,
        IEnclaveLease::registerMachineCall {
            kind: 1,
            attestation: q,
            endpoint: "x".into(),
            cpus: 1,
            memGiB: 1,
            gpu: String::new()
        },
    ));
}

#[test]
fn a_platform_falling_out_of_date_degrades_its_lease() {
    let mut t = tee();
    let m1 = t.sim.platform(1);
    let operator = t.operator;
    let machine = t.register(operator, &m1);
    let id = t.lease(machine, bolt(10));
    let enclave = PrivateKeySigner::random();
    assert!(t.activate(id, &m1, &enclave));
    let relayer = t.relayer;
    // Still up to date: nothing changes.
    t.evm.call(relayer, LEASES, U256::ZERO, IEnclaveLease::recheckCall { id });
    assert!(!t.lease_view(id).degraded);
    // Intel publishes a newer TCB level.
    let newer = t.sim.tcb_info(2, false);
    let (_, signer) = t.col.set_tcb_info(&newer, LATER).unwrap();
    t.evm.call(
        relayer,
        COLLATERAL,
        U256::ZERO,
        ITeeCollateral::setTcbInfoCall { document: newer.into_bytes().into(), signer },
    );
    let st = t.evm.call(relayer, LEASES, U256::ZERO, IEnclaveLease::recheckCall { id });
    assert_eq!(st, 5);
    assert!(t.lease_view(id).degraded);
    assert_eq!(t.evm.view(LEASES, IEnclaveLease::activeSignerCall { id }), Address::ZERO);
    // No more payment; the renter may move at once.
    t.evm.timestamp += 3600;
    assert!(t.checkpoint(id, &enclave, 1, B256::repeat_byte(1)));
    assert_eq!(t.lease_view(id).hoursPaid, 0);
}

#[test]
fn t2_machines_are_verified_by_the_panel() {
    let mut t = tee();
    let ca = SimTpmCa::new(b"vendor");
    let mut soft = SoftTpm::new(b"t2-machine", &ca);
    soft.boot(b"bolt-art t2");
    let operator = t.operator;
    let binding = t.evm.view(LEASES, IEnclaveLease::machineBindingCall { operator });
    let ev = soft.evidence(tpm::DEFAULT_PCRS, binding.as_slice());
    let m = t.evm.call(
        operator,
        LEASES,
        U256::ZERO,
        IEnclaveLease::registerMachineCall {
            kind: 3,
            attestation: ev.digest().to_vec().into(),
            endpoint: "https://t2.example".into(),
            cpus: 20,
            memGiB: 128,
            gpu: "GB10".into(),
        },
    );
    assert!(!t.evm.view(LEASES, IEnclaveLease::machineCall { m }).verified);
    let pending = t.evm.view(LEASES, IEnclaveLease::pendingAttestationsCall {});
    assert_eq!(pending.len(), 1);
    // The panel appraises the evidence off chain…
    let a = tpm::appraise(&ev, &[ca.root_der()], LATER).unwrap();
    assert_eq!(a.qualifying_data, binding.as_slice());
    // …and the node records its certified result.
    t.evm
        .system(LEASES, IEnclaveLease::assignAttestationsCall { epoch: 3, members: vec![0, 1, 2] });
    assert!(t.evm.system(
        LEASES,
        IEnclaveLease::recordAttestationCall { r: pending[0], ok: true, machineId: a.machine_id },
    ));
    let mc = t.evm.view(LEASES, IEnclaveLease::machineCall { m });
    assert!(mc.verified);
    assert_eq!(mc.machineId, soft.machine_id());
    t.evm.call(
        operator,
        LEASES,
        U256::ZERO,
        IEnclaveLease::setOfferCall { m, pricePerHour: bolt(1).to::<u128>(), available: true },
    );
    // The image registers the T2 measurement.
    let image = t.image;
    let renter = t.renter;
    t.evm.call(
        renter,
        IMAGES,
        U256::ZERO,
        IImageRegistry::addMeasurementCall {
            id: image,
            kind: 3,
            raw: tpm::measurement_bytes(a.pcr_mask, &a.pcrs).into(),
            platform: "simulated TPM".into(),
        },
    );
    assert!(
        t.evm.view(IMAGES, IImageRegistry::allowsCall { id: image, kind: 3, m: a.measurement })
    );

    let id = t.lease(m, bolt(10));
    let enclave = PrivateKeySigner::random();
    let enc = B256::repeat_byte(0xee);
    let b = t.evm.view(
        LEASES,
        IEnclaveLease::enclaveBindingCall { id, signer: enclave.address(), encKey: enc },
    );
    let ev = soft.evidence(tpm::DEFAULT_PCRS, tpm::activation_data(b, AGENT).as_slice());
    // Only the renter or the operator queues a T2 activation.
    assert!(!t.evm.try_call(
        t.relayer,
        LEASES,
        U256::ZERO,
        IEnclaveLease::activateCall {
            id,
            signer: enclave.address(),
            encKey: enc,
            attestation: ev.digest().to_vec().into()
        },
    ));
    t.evm.call(
        operator,
        LEASES,
        U256::ZERO,
        IEnclaveLease::activateCall {
            id,
            signer: enclave.address(),
            encKey: enc,
            attestation: ev.digest().to_vec().into(),
        },
    );
    assert_eq!(t.lease_view(id).state, 2);
    let r = t.evm.view(LEASES, IEnclaveLease::requestCountCall {});
    t.evm
        .system(LEASES, IEnclaveLease::assignAttestationsCall { epoch: 4, members: vec![0, 1, 2] });
    // A result naming another machine is a rejection.
    assert!(t.evm.system(
        LEASES,
        IEnclaveLease::recordAttestationCall { r, ok: true, machineId: B256::repeat_byte(1) },
    ));
    assert_eq!(t.lease_view(id).state, 1);
    // Retry.
    t.evm.call(
        operator,
        LEASES,
        U256::ZERO,
        IEnclaveLease::activateCall {
            id,
            signer: enclave.address(),
            encKey: enc,
            attestation: ev.digest().to_vec().into(),
        },
    );
    t.evm
        .system(LEASES, IEnclaveLease::assignAttestationsCall { epoch: 5, members: vec![0, 1, 2] });
    assert!(t.evm.system(
        LEASES,
        IEnclaveLease::recordAttestationCall {
            r: r + U256::from(1),
            ok: true,
            machineId: a.machine_id
        },
    ));
    assert_eq!(t.evm.view(LEASES, IEnclaveLease::activeSignerCall { id }), enclave.address());
    // Outsiders cannot record results.
    assert!(!t.evm.try_call(
        renter,
        LEASES,
        U256::ZERO,
        IEnclaveLease::recordAttestationCall { r, ok: true, machineId: a.machine_id },
    ));
}

#[test]
fn the_limited_wallet_lets_the_enclave_spend_within_limits() {
    let mut t = tee();
    let m1 = t.sim.platform(1);
    let operator = t.operator;
    let machine = t.register(operator, &m1);
    let id = t.lease(machine, bolt(10));
    let enclave = PrivateKeySigner::random();
    assert!(t.activate(id, &m1, &enclave));

    // An account delegated to the wallet (EIP-7702 designator).
    let owner = Address::repeat_byte(0x0a);
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend_from_slice(WALLET.as_slice());
    t.evm.deploy_at(owner, &code.into());
    t.evm.fund(owner, bolt(100));
    let shop = Address::repeat_byte(0x5b);
    let elsewhere = Address::repeat_byte(0x5c);
    t.evm.call(
        owner,
        owner,
        U256::ZERO,
        ILimitedWallet::configureCall {
            lease: id,
            dailyLimit: bolt(3).to::<u128>(),
            perTxLimit: bolt(2).to::<u128>(),
            targets: vec![shop],
        },
    );
    let pay = |to: Address, n: u64| ILimitedWallet::Call { to, value: bolt(n), data: Bytes::new() };
    let signed = |t: &mut Tee, calls: Vec<ILimitedWallet::Call>, who: &PrivateKeySigner| -> bool {
        let (_, _, _, _, nonce, _) = {
            let c = crate::queries::call(
                &t.evm.db,
                t.evm.chain_id,
                owner,
                ILimitedWallet::configCall {},
            )
            .unwrap();
            (c.lease, c.dailyLimit, c.perTxLimit, c.spentToday, c.nonce, c.targets)
        };
        let deadline = U256::from(t.evm.timestamp + 600);
        let digest = crate::queries::call(
            &t.evm.db,
            t.evm.chain_id,
            owner,
            ILimitedWallet::executeDigestCall { calls: calls.clone(), nonce, deadline },
        )
        .unwrap();
        let sig = who.sign_hash_sync(&digest).unwrap();
        let relayer = t.relayer;
        t.evm.try_call(
            relayer,
            owner,
            U256::ZERO,
            ILimitedWallet::executeSignedCall {
                calls,
                deadline,
                sig: sig.as_bytes().to_vec().into(),
            },
        )
    };
    assert!(signed(&mut t, vec![pay(shop, 2)], &enclave));
    assert_eq!(t.evm.balance(shop), bolt(2));
    // Over the per-transaction limit, over the daily limit, to an unlisted target, by another key.
    assert!(!signed(&mut t, vec![pay(shop, 3)], &enclave));
    assert!(!signed(&mut t, vec![pay(shop, 1), pay(shop, 1)], &enclave));
    assert!(!signed(&mut t, vec![pay(elsewhere, 1)], &enclave));
    assert!(!signed(&mut t, vec![pay(shop, 1)], &PrivateKeySigner::random()));
    assert!(signed(&mut t, vec![pay(shop, 1)], &enclave));
    // A new day.
    t.evm.timestamp += 86_400;
    assert!(signed(&mut t, vec![pay(shop, 1)], &enclave));
    // The owner is not limited; and when it revokes, the enclave is out.
    t.evm.call(
        owner,
        owner,
        U256::ZERO,
        ILimitedWallet::executeCall { calls: vec![pay(elsewhere, 10)] },
    );
    t.evm.call(owner, owner, U256::ZERO, ILimitedWallet::revokeCall {});
    assert!(!signed(&mut t, vec![pay(shop, 1)], &enclave));
    // Configured again: a lease that ends takes the key with it.
    t.evm.call(
        owner,
        owner,
        U256::ZERO,
        ILimitedWallet::configureCall {
            lease: id,
            dailyLimit: bolt(3).to::<u128>(),
            perTxLimit: bolt(2).to::<u128>(),
            targets: vec![shop],
        },
    );
    assert!(signed(&mut t, vec![pay(shop, 1)], &enclave));
    let renter = t.renter;
    t.evm.call(renter, LEASES, U256::ZERO, IEnclaveLease::terminateCall { id });
    assert!(!signed(&mut t, vec![pay(shop, 1)], &enclave));
}
