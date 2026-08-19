// enclave/enclave_grpc/src/attestation/mod.rs
//
// Phase 12 — IETF RATS EAT attestation & TEE silicon binding.
//
//   tdx.rs      — Intel TDX quote request via /dev/tdx-guest (Linux)
//   sev_snp.rs  — AMD SEV-SNP report via /dev/sev-guest (Linux)
//   eat_builder.rs — RFC 9334 EAT claims + COSE-Sign1 (RFC 9052) encoding
//   verifier.rs — offline claim validation (swname / image digest / sig)

pub mod eat_builder;
pub mod sev_snp;
pub mod tdx;
pub mod verifier;
