// enclave/enclave_grpc/benches/zktls_bench.rs
//
// Phase 14 (Prompts 276-277) — zkTLS proof generation latency benchmark.
//
// Measures the FULL proof pipeline the sub-second attestation path pays:
//   1. jq selector evaluation over a real JSON payload (jaq-all, the same
//      engine the FDC attestor network runs),
//   2. hashing (sha256 of url/data/response + keccak256 of the canonical
//      payload),
//   3. secp256k1 ECDSA signing (k256 recoverable signature).
//
// Target: TOTAL processing latency under 500 ms (master plan requirement).
// The TLS handshake is excluded — that is the network RTT, not enclave
// compute; the benchmark measures the enclave-side proof generation that
// happens once the decrypted payload is in RAM.
//
// Run: cargo bench --bench zktls_bench

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use enclave_grpc::zktls::cert_verifier::CapturedChain;
use enclave_grpc::zktls::proof_generator::generate_proof;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;

/// A realistic Web2 JSON document (the shape the FDC-attested host family
/// serves — a TODO-item document; verified live on Coston2 2026-08-11).
const RESPONSE: &[u8] = br#"{"userId":1,"id":1,"title":"delectus aut autem","completed":true}"#;
const URL: &str = "https://jsonplaceholder.typicode.com/todos/1";
const SELECTOR: &str = ".completed";

/// The cert chain the proof binds (a real captured chain in production;
/// the bench uses a fixed DER-shaped chain — the fingerprint is sha256 over
/// it, and the time cost is identical regardless of content).
fn bench_chain() -> CapturedChain {
    let end_entity = vec![0x30u8; 512];
    let intermediate = vec![0x30u8; 512];
    CapturedChain {
        server: "jsonplaceholder.typicode.com".to_string(),
        end_entity,
        intermediates: vec![intermediate],
    }
}

fn bench_proof_pipeline(c: &mut Criterion) {
    let signer = SigningKey::random(&mut OsRng);
    let chain = bench_chain();

    c.bench_function(
        "zktls_proof_generation_total",
        |b| {
            b.iter_batched(
                || {
                    // Fresh nonce per iteration (real randomness) — the
                    // production path mints one per proof.
                    use k256::elliptic_curve::rand_core::RngCore;
                    let mut nonce = [0u8; 16];
                    OsRng.fill_bytes(&mut nonce);
                    nonce
                },
                |nonce| {
                    black_box(
                        generate_proof(
                            URL,
                            RESPONSE,
                            SELECTOR,
                            &chain,
                            &signer,
                            nonce,
                            None,
                        )
                        .expect("proof builds"),
                    )
                },
                BatchSize::SmallInput,
            )
        },
    );

    // Breakdown: the jq evaluation alone (the most likely hot spot).
    c.bench_function("jq_select_only", |b| {
        b.iter(|| {
            black_box(
                enclave_grpc::zktls::proof_generator::jq_select(RESPONSE, SELECTOR)
                    .expect("jq runs"),
            )
        })
    });
}

criterion_group!(benches, bench_proof_pipeline);
criterion_main!(benches);
