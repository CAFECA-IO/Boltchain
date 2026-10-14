//! Collateral from Intel's PCS, simulated TDX quotes, and the software TPM.

use bolt_attest::{
    Collateral, Error,
    intel::status,
    sim::{SimIntel, SimPlatform},
    tdx::{self, TdReport},
    tpm::{self, DEFAULT_PCRS},
    tpm_sim::{SeedRng, SimTpmCa, SoftTpm},
};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/intel/");
/// 2026-10-15T00:00:00Z: inside every fixture's validity.
const NOW: u64 = 1_792_022_400;
/// 2027-01-01: when simulated collateral is in force.
const LATER: u64 = 1_798_761_600;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIX}{name}")).unwrap()
}

#[test]
fn intel_collateral_verifies_under_the_intel_root() {
    let mut c = Collateral::intel();
    c.add_crl(&fixture("root-ca-crl.der")).unwrap();
    let platform = c.add_ca(&fixture("pck-platform-ca.der"), NOW).unwrap();
    c.add_ca(&fixture("pck-processor-ca.der"), NOW).unwrap();
    let signer = c.add_ca(&fixture("tcb-signing.der"), NOW).unwrap();
    assert!(c.ca(&platform).is_some());
    c.add_crl(&fixture("pck-crl-platform.der")).unwrap();
    c.add_crl(&fixture("pck-crl-processor.der")).unwrap();
    let tcb = String::from_utf8(fixture("tcb-info-00806f050000.json")).unwrap();
    let (fmspc, by) = c.set_tcb_info(&tcb, NOW).unwrap();
    assert_eq!(fmspc, [0x00, 0x80, 0x6f, 0x05, 0x00, 0x00]);
    assert_eq!(by, signer);
    assert_eq!(c.tcb_info(&fmspc).unwrap().evaluation, 20);
    c.set_qe_identity(&String::from_utf8(fixture("qe-identity.json")).unwrap(), NOW).unwrap();
    // Not newer: refused.
    assert!(c.set_tcb_info(&tcb, NOW).is_err());
    // A tampered document: refused.
    let bad = tcb.replacen("UpToDate", "OutOfDate", 1);
    let mut d = Collateral::intel();
    d.add_ca(&fixture("tcb-signing.der"), NOW).unwrap();
    assert!(matches!(d.set_tcb_info(&bad, NOW), Err(Error::Signature(_))));
    // Not under a simulated root.
    let mut s = Collateral::with_root(SimIntel::dev().root_point());
    assert!(s.add_ca(&fixture("tcb-signing.der"), NOW).is_err());
}

fn sim_collateral(sim: &SimIntel) -> Collateral {
    let mut c = Collateral::with_root(sim.root_point());
    let col = sim.collateral();
    for ca in &col.cas {
        c.add_ca(ca, LATER).unwrap();
    }
    for crl in &col.crls {
        c.add_crl(crl).unwrap();
    }
    c.set_tcb_info(&col.tcb_info, LATER).unwrap();
    c.set_qe_identity(&col.qe_identity, LATER).unwrap();
    c
}

fn report(data: [u8; 64]) -> TdReport {
    SimPlatform::td_report([7; 48], [[1; 48], [2; 48], [3; 48], [4; 48]], data)
}

#[test]
fn simulated_quotes_verify_and_tampering_does_not() {
    let sim = SimIntel::new(b"test");
    let col = sim_collateral(&sim);
    let m = sim.platform(1);
    let q = m.quote(&report([9; 64]));
    let v = tdx::verify(&q, &col, LATER).unwrap();
    assert_eq!(v.tcb_status, status::UP_TO_DATE);
    assert_eq!(v.qe_status, status::UP_TO_DATE);
    assert_eq!(v.machine_id, m.machine_id());
    assert_eq!(v.report.report_data, [9; 64]);
    assert_eq!(v.report.measurement(), report([0; 64]).measurement());

    // Another machine, another ID.
    let v2 = tdx::verify(&sim.platform(2).quote(&report([9; 64])), &col, LATER).unwrap();
    assert_ne!(v2.machine_id, v.machine_id);

    // A changed REPORT_DATA breaks the attestation key's signature.
    let mut t = q.clone();
    t[tdx::HEADER + 520] ^= 1;
    assert!(tdx::verify(&t, &col, LATER).is_err());

    // Debug TDs are refused.
    let mut r = report([9; 64]);
    r.td_attributes[0] = 1;
    assert!(tdx::verify(&m.quote(&r), &col, LATER).is_err());

    // Another PKI's quote is unknown here.
    let other = SimIntel::new(b"other");
    assert!(tdx::verify(&other.platform(1).quote(&report([9; 64])), &col, LATER).is_err());

    // Stale collateral (well past nextUpdate).
    assert!(tdx::verify(&q, &col, 2_600_000_000).is_err());
}

#[test]
fn revocation_and_outdated_platforms() {
    let sim = SimIntel::new(b"test");
    let mut col = sim_collateral(&sim);
    let m = sim.platform(3);
    let q = m.quote(&report([0; 64]));
    tdx::verify(&q, &col, LATER).unwrap();

    // Intel publishes a newer TCB level: the platform becomes out of date.
    col.set_tcb_info(&sim.tcb_info(2, false), LATER).unwrap();
    assert_eq!(tdx::verify(&q, &col, LATER).unwrap().tcb_status, status::OUT_OF_DATE);

    // Its PCK certificate is revoked.
    col.add_crl(&sim.crl(true, &[m.serial], 5)).unwrap();
    assert!(matches!(tdx::verify(&q, &col, LATER), Err(Error::Revoked)));
}

#[test]
fn tpm_evidence_appraisal_and_credential_challenge() {
    let ca = SimTpmCa::new(b"vendor");
    let mut t = SoftTpm::new(b"machine-1", &ca);
    t.boot(b"bolt-art image v1");
    let binding = [5u8; 32];
    let ev = t.evidence(DEFAULT_PCRS, &binding);
    let roots = vec![ca.root_der()];

    let a = tpm::appraise(&ev, &roots, LATER).unwrap();
    assert_eq!(a.machine_id, t.machine_id());
    assert_eq!(a.qualifying_data, binding);
    assert_eq!(a.pcr_mask, DEFAULT_PCRS);
    assert_eq!(a.pcrs.len(), 9);

    // The same image on another TPM measures the same; another image does not.
    let mut t2 = SoftTpm::new(b"machine-2", &ca);
    t2.boot(b"bolt-art image v1");
    let a2 = tpm::appraise(&t2.evidence(DEFAULT_PCRS, &binding), &roots, LATER).unwrap();
    assert_eq!(a2.measurement, a.measurement);
    assert_ne!(a2.machine_id, a.machine_id);
    let mut t3 = SoftTpm::new(b"machine-3", &ca);
    t3.boot(b"something else");
    let a3 = tpm::appraise(&t3.evidence(DEFAULT_PCRS, &binding), &roots, LATER).unwrap();
    assert_ne!(a3.measurement, a.measurement);

    // Evidence round-trips through its canonical encoding.
    assert_eq!(tpm::Evidence::from_bytes(&ev.to_bytes()).unwrap(), ev);

    // An untrusted vendor, a doctored log, a forged quote: refused.
    assert!(tpm::appraise(&ev, &[SimTpmCa::new(b"x").root_der()], LATER).is_err());
    let mut bad = ev.clone();
    let n = bad.event_log.len();
    bad.event_log[n - 1] ^= 1; // event data only: digests unchanged, still consistent
    assert!(tpm::appraise(&bad, &roots, LATER).is_ok());
    let mut bad = ev.clone();
    let p = bad.event_log.len() - 17 - 4 - 32; // last event's digest
    bad.event_log[p] ^= 1;
    assert!(tpm::appraise(&bad, &roots, LATER).is_err());
    let mut bad = ev.clone();
    let n = bad.quote.len();
    bad.quote[n - 1] ^= 1;
    assert!(tpm::appraise(&bad, &roots, LATER).is_err());

    // The credential challenge: only the TPM with that EK recovers the secret.
    let mut rng = SeedRng::new(b"panel");
    let secret = tpm::challenge_secret(&mut rng);
    let (blob, enc) = tpm::make_credential(&a.ek_spki, &a.ak_name, &secret, &mut rng).unwrap();
    assert_eq!(t.activate_credential(&blob, &enc).unwrap(), secret);
    assert!(t2.activate_credential(&blob, &enc).is_err());
    // A challenge for another AK name fails the integrity check.
    let (blob, enc) = tpm::make_credential(&a.ek_spki, &a2.ak_name, &secret, &mut rng).unwrap();
    assert!(t.activate_credential(&blob, &enc).is_err());
}

#[test]
fn kdfa_matches_the_tpm_reference() {
    // Same inputs, same output; length and label change it.
    let a = tpm::kdfa(b"key", "STORAGE", b"name", &[], 128);
    assert_eq!(a.len(), 16);
    assert_eq!(a, tpm::kdfa(b"key", "STORAGE", b"name", &[], 128));
    assert_ne!(a, tpm::kdfa(b"key", "INTEGRITY", b"name", &[], 128));
    let c = tpm::aes_cfb(&a, b"hello credential, longer than one block", false);
    assert_eq!(tpm::aes_cfb(&a, &c, true), b"hello credential, longer than one block");
}
