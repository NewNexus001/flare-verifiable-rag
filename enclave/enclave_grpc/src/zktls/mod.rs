// enclave/enclave_grpc/src/zktls/mod.rs
//
// Phase 14 — Sub-Second TEE zkTLS Proxy Engine (Prompts 261-265).
//
// The master plan's zkTLS design: the enclave opens a DIRECT TLS 1.3 session
// with a target Web2 API from inside the Intel TDX hardware boundary. The
// session keys live only in hardware-encrypted volatile memory, the server's
// X.509 chain is verified against the Mozilla root bundle, and the enclave
// then signs a proof binding (url, selected jq output, response hash, cert
// chain fingerprint) with its secp256k1 identity key — a proof any verifier
// (including VerifiableRAG.sol / ZkTlsRelayer.sol on-chain) can check via
// ecrecover, WITHOUT the 90-second FDC voting round.
//
// Module layout:
//   cert_verifier  — CapturingVerifier: records the presented certificate
//                    chain during the TLS handshake, then delegates to the
//                    REAL WebPkiVerifier (webpki-roots 0.25 Mozilla bundle)
//                    for validation (Prompt 263). Capture-then-verify: only
//                    chains that VALIDATE are ever recorded.
//   proxy          — ZkTlsProxy: tokio-rustls 0.24 (rustls 0.21) TLS 1.3
//                    outbound connections over hyper 0.14, with the
//                    capturing verifier wired into the ClientConfig
//                    (Prompts 261-262). Request headers are consumed by the
//                    request and NEVER enter the proof path (Prompt 278).
//   proof_generator — jq selector evaluation over the decrypted payload
//                    (jaq-all, the professional jq engine — same semantics
//                    as the Flare FDC attestor network) + the signed
//                    ZkTlsProof structure (Prompts 264-265).
//
// Honest scope note (project no-lies rule): a true zero-knowledge proof over
// the TLS transcript (the TLSNotary/MPC-TLS model) is a research-grade
// construction; this implementation is the TEE-enshrined model the master
// plan itself describes — the TLS session runs inside the hardware
// attestation boundary and the enclave's attested identity key signs the
// transcript binding. The trust anchor is the TEE attestation, exactly as
// the plan's "The enclave signs the zkTLS proof using its hardware-bound
// ECDSA identity key" states. Nothing is simulated: real TLS 1.3, real
// Mozilla-root chain verification, real jq semantics, real secp256k1
// signatures verified by ecrecover on-chain.

pub mod cert_verifier;
pub mod proof_generator;
pub mod proxy;
