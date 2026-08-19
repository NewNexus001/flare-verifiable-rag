// enclave/enclave_grpc/tests/test_tdx_emulator.rs
//
// Phase 12 (Prompt 230) — end-to-end token generation via the emulator shim.
//
// Two guarantees, both tested here:
//   1. The PRODUCTION path (attestation::tdx) FAILS CLOSED on hosts without
//      real TDX hardware — it never consults the emulator.
//   2. The full attestation pipeline (reportdata → report → EAT → verify)
//      works end-to-end, proven here with the test-only emulator so it can
//      run on any dev host.
#[path = "mock_tdx_device.rs"]
mod mock_tdx_device;

use enclave_grpc::attestation::eat_builder::{
    build_eat, nonce_to_reportdata, parse_cose_sign1, DEFAULT_SWNAME, EatClaims,
};
use enclave_grpc::attestation::tdx;
use enclave_grpc::attestation::verifier::{validate_claims, verify_cose_sign1};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;

const DIGEST: &str =
    "sha256:8a1a98fa247bc0895b40ec16e89de96f0d935bd5be11bde02744f373ef207d6e";

#[test]
fn production_tdx_path_fails_closed_without_hardware() {
    // If a REAL device exists, the production path may legitimately succeed —
    // but on this host (no /dev/tdx-guest) it MUST return a typed error and
    // MUST NOT fall back to the emulator (which is what fail-closed means).
    if mock_tdx_device::real_device_present() {
        return;
    }
    let reportdata = nonce_to_reportdata(b"production-probe");
    let res = tdx::get_tdreport(&reportdata);
    assert!(res.is_err(), "production path must fail closed without TEE hardware");
}

#[test]
fn emulator_to_eat_to_verify_end_to_end() {
    let reportdata = nonce_to_reportdata(b"session-42");
    let report = mock_tdx_device::emulated_tdreport(&reportdata);
    assert_eq!(report.len(), tdx::TDX_REPORT_LEN);

    let mut rng = OsRng;
    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);

    let claims = EatClaims {
        nonce: reportdata.to_vec(),
        swname: DEFAULT_SWNAME.to_string(),
        image_digest: DIGEST.to_string(),
        hardware: "intel-tdx (emulator)".to_string(),
        instance_id: [1u8; 16],
        iat: 1_700_000_000,
        measurements: vec![report[..32].try_into().unwrap()],
    };

    let token = build_eat(&claims, &signing_key).unwrap();
    assert!(!token.is_empty());

    // Round-trip: parse → verify signature → validate policy.
    let parsed = parse_cose_sign1(&token).unwrap();
    assert!(!parsed.signature.is_empty());

    let payload = verify_cose_sign1(&token, &verifying_key).unwrap();
    let verified = validate_claims(
        &payload,
        DEFAULT_SWNAME,
        Some(DIGEST),
        Some(&reportdata),
    )
    .unwrap();

    assert_eq!(verified.swname, DEFAULT_SWNAME);
    assert_eq!(verified.image_digest, DIGEST);
    assert_eq!(verified.hardware, claims.hardware);
    assert_eq!(verified.nonce, reportdata);
}

#[test]
fn emulator_output_is_deterministic() {
    let a = mock_tdx_device::emulated_tdreport(&[9u8; 64]);
    let b = mock_tdx_device::emulated_tdreport(&[9u8; 64]);
    assert_eq!(a, b);
    let c = mock_tdx_device::emulated_tdreport(&[8u8; 64]);
    assert_ne!(a, c);
}
