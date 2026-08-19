// enclave/enclave_grpc/tests/mock_tdx_device.rs
//
// Phase 12 (Prompt 229) — TEST-ONLY Intel TDX device emulator.
//
// This shim is for DEVELOPMENT TESTS ONLY. The PRODUCTION path
// (enclave_grpc::attestation::tdx::get_tdreport) touches ONLY the real
// /dev/tdx-guest device and FAILS CLOSED everywhere else — it never imports
// or consults this module. See test_tdx_emulator.rs, which asserts exactly
// that (production fail-closed) before using the emulator to exercise the
// EAT pipeline end-to-end on hosts without TDX hardware.

/// Deterministic TDREPORT-shaped payload (exactly TDX_REPORT_LEN = 1024
/// bytes) derived from the caller's reportdata via repeated SHA-256
/// expansion. Deterministic on purpose: tests can assert stable outputs.
pub fn emulated_tdreport(reportdata: &[u8; 64]) -> [u8; 1024] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 1024];
    let mut seed = reportdata.to_vec();
    let mut pos = 0usize;
    while pos < out.len() {
        let digest = Sha256::digest(&seed);
        let n = digest.len().min(out.len() - pos);
        out[pos..pos + n].copy_from_slice(&digest[..n]);
        seed = digest.to_vec();
        pos += n;
    }
    out
}

/// Probe whether a REAL TDX device is present (mirrors the production open
/// semantics). Used by tests to assert production fail-closed behavior.
pub fn real_device_present() -> bool {
    std::path::Path::new("/dev/tdx-guest").exists()
}
