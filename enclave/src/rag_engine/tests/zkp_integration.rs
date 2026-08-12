//! # Prompt 058 — ZKP integration tests (proof generation & verification)
//!
//! These tests exercise the crate's **public** ZKP API exactly as an
//! external consumer (the Python enclave gateway, and later the on-chain
//! `VerifiableRAG.sol` verifier) would: `indexer_rs::` re-exports only, no
//! private access. Compiling this file *is* part of the test — a missing or
//! renamed re-export fails the build here.
//!
//! Scope (what "integration" means here, per the research-backed pattern):
//!
//! - **Real IPA pipeline, not `MockProver`.** `MockProver` only checks
//!   constraint satisfaction locally; it never exercises polynomial
//!   commitments, the Fiat–Shamir transcript, or proof
//!   serialization/deserialization. These tests run the real
//!   `Params` → `keygen` → `create_proof` → `verify_proof` chain that the
//!   production enclave runs, over the Pasta curve (`Fp` / `EqAffine`).
//! - **Honest round-trip.** Key generation runs once against the
//!   witness-free circuit (the production setup/prove split); proving runs
//!   with real evidence-derived witnesses (document hash, prompt hash, and
//!   the hash of an *actual* `KnowledgeGraph::find_path` evidence subgraph —
//!   no canned values); verification must accept the honest proof.
//! - **Tamper rejection.** A corrupted proof, a tampered public input, a
//!   truncated proof, and arbitrary garbage bytes must all be rejected with
//!   a structured `Err` — **never a panic** (attacker-controlled input
//!   safety, the crate's documented contract).
//! - **Zero-knowledge property.** Identical witnesses must yield
//!   byte-different proofs across runs (fresh blinding factors), and *both*
//!   must verify against the same key.
//!
//! k-values: integration tests use `k = 6` (64 rows) for the explicit
//! params/keygen/prove path — research-backed headroom above the ~22 rows a
//! 3-public-input circuit needs. The one-call API (`generate_proof` /
//! `verify_proof`) uses the crate's compiled-in `DEFAULT_K = 8`, the same
//! setup the enclave process will use.

use indexer_rs::{
    digest_to_field, generate_params, generate_proof, graph_output_to_field, keygen, prove, verify,
    verify_proof, KnowledgeGraph, Path, RAGVerificationCircuit, ZkpError,
};

use halo2_proofs::pasta::Fp;

// `Fp::ONE` (and field arithmetic) comes from the `ff::Field` trait, exactly
// as it does inside the crate modules.
use ff::Field;

// ---------------------------------------------------------------------------
// Shared fixtures — real evidence, never canned
// ---------------------------------------------------------------------------

/// A small real knowledge graph with one predicate edge.
fn evidence_graph() -> KnowledgeGraph {
    let mut g = KnowledgeGraph::new();
    let a = g.add_entity("flare").expect("add entity");
    let b = g.add_entity("ftso").expect("add entity");
    g.add_relation(a, "operates", b).expect("add relation");
    g
}

/// Real evidence-derived witnesses: `H_doc`, `H_prompt`, `H_out`, where
/// `H_out` is the SHA-256 digest of the *actual* serialized evidence
/// subgraph returned by the deterministic symbolic engine.
fn real_witnesses() -> (Fp, Fp, Fp) {
    let doc = digest_to_field(b"document: flare network coverage report");
    let prompt = digest_to_field(b"prompt: what is the FTSO v2 staleness bound?");
    let graph = evidence_graph();
    let path = graph.find_path("flare", "operates").expect("evidence");
    let out = graph_output_to_field(&path);
    (doc, prompt, out)
}

/// Builds an honest proof through the full public pipeline
/// (`generate_params` → `keygen` → `prove`) and returns params, pk and
/// proof, so tests can verify and then tamper.
fn honest_roundtrip(
    k: u32,
) -> (
    halo2_proofs::poly::commitment::Params<halo2_proofs::pasta::EqAffine>,
    halo2_proofs::plonk::ProvingKey<halo2_proofs::pasta::EqAffine>,
    Vec<Fp>,
    Vec<u8>,
) {
    let params = generate_params(k).expect("k in 4..=24 is supported");
    let (doc, prompt, out) = real_witnesses();
    let circuit = RAGVerificationCircuit::with_values(doc, prompt, out);
    let public_inputs = vec![doc, prompt, out];

    // Keygen MUST run against the witness-free circuit (production pattern).
    let pk = keygen(&params, &RAGVerificationCircuit::<Fp>::unknown())
        .expect("keygen on the fixed circuit must succeed");
    let proof = prove(&params, &pk, &circuit, &public_inputs).expect("prove must succeed");

    (params, pk, public_inputs, proof)
}

// ---------------------------------------------------------------------------
// 1. Honest round-trip — the happy path
// ---------------------------------------------------------------------------

#[test]
fn full_keygen_prove_verify_roundtrip_accepts_honest_proof() {
    let (params, pk, public_inputs, proof) = honest_roundtrip(6);

    assert!(
        !proof.is_empty(),
        "a real IPA/Blake2b transcript must be non-empty (real proof bytes)"
    );

    verify(&params, pk.get_vk(), &public_inputs, &proof)
        .expect("an honest proof generated by the real pipeline must verify");
}

// ---------------------------------------------------------------------------
// 2. Tamper rejection — the adversarial suite
// ---------------------------------------------------------------------------

#[test]
fn tampered_proof_bytes_are_rejected() {
    let (params, pk, public_inputs, proof) = honest_roundtrip(6);

    // Bit-flip a byte in the middle of the serialized proof. The transcript
    // must reject the corrupted commitment data with a clean Err.
    let mut corrupt = proof.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xFF;

    assert!(
        verify(&params, pk.get_vk(), &public_inputs, &corrupt).is_err(),
        "a single corrupted proof byte must invalidate the proof"
    );
}

#[test]
fn tampered_public_inputs_are_rejected() {
    let (params, pk, public_inputs, proof) = honest_roundtrip(6);
    let (doc, prompt, out) = (public_inputs[0], public_inputs[1], public_inputs[2]);

    // Tamper EACH of the three public inputs independently — the binding
    // must fail for any of them.
    let tampered = [
        vec![out, prompt, out],           // H_doc replaced
        vec![doc, doc, out],              // H_prompt replaced
        vec![doc, prompt, doc],           // H_out replaced
        vec![doc, prompt, out + Fp::ONE], // H_out nudged
    ];
    for inputs in tampered {
        assert!(
            verify(&params, pk.get_vk(), &inputs, &proof).is_err(),
            "proof must not verify against tampered public input {inputs:?}"
        );
    }
}

#[test]
fn truncated_proof_is_rejected_cleanly_never_panics() {
    let (params, pk, public_inputs, proof) = honest_roundtrip(6);

    // Fuzz-style truncation at strategic cut points. The Blake2bRead
    // transcript surfaces UnexpectedEof as a structured error — the
    // no-panic property is structural, and sampling points keeps the suite
    // fast.
    let len = proof.len();
    for cut in [
        0usize,
        1,
        len / 4,
        len / 2,
        3 * len / 4,
        len.saturating_sub(1),
    ] {
        let truncated = &proof[..cut];
        assert!(
            verify(&params, pk.get_vk(), &public_inputs, truncated).is_err(),
            "truncated proof at byte {cut} must be rejected cleanly, not panic"
        );
    }
}

#[test]
fn garbage_proof_bytes_are_rejected_cleanly_never_panics() {
    let params = generate_params(6).expect("k in 4..=24 is supported");
    let (doc, prompt, out) = real_witnesses();
    let public_inputs = vec![doc, prompt, out];
    let pk =
        keygen(&params, &RAGVerificationCircuit::<Fp>::unknown()).expect("keygen must succeed");

    // Deterministic xorshift garbage — no external RNG dependency.
    let mut seed = 0x5EED_u64;
    for len in [1usize, 8, 32, 128, 512] {
        let garbage: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed & 0xFF) as u8
            })
            .collect();
        assert!(
            verify(&params, pk.get_vk(), &public_inputs, &garbage).is_err(),
            "garbage proof of {len} bytes must be rejected cleanly, not panic"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. One-call API (Prompt 052/053) — the enclave entry points
// ---------------------------------------------------------------------------

#[test]
fn generate_proof_verify_proof_roundtrip_succeeds() {
    let (doc, prompt, out) = real_witnesses();
    let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

    assert!(!proof.is_empty(), "real proof bytes must be non-empty");
    verify_proof(&proof, &[doc, prompt, out])
        .expect("proof from the cached setup must verify against its own VK");
}

#[test]
fn generate_proof_is_randomized_but_every_proof_verifies() {
    let (doc, prompt, out) = real_witnesses();

    // Zero-knowledge property: identical witnesses, fresh blinding factors.
    let a = generate_proof(doc, prompt, out).expect("first proof");
    let b = generate_proof(doc, prompt, out).expect("second proof");
    assert_ne!(
        a, b,
        "halo2 proofs are randomized: identical inputs must yield different bytes"
    );

    let public_inputs = [doc, prompt, out];
    verify_proof(&a, &public_inputs).expect("first proof must verify");
    verify_proof(&b, &public_inputs).expect("second proof must verify");
}

#[test]
fn one_call_api_rejects_tampered_public_input() {
    let (doc, prompt, out) = real_witnesses();
    let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

    let tampered = [doc, prompt, out + Fp::ONE];
    assert!(
        verify_proof(&proof, &tampered).is_err(),
        "tampered public input must be rejected by the one-call verifier"
    );
}

#[test]
fn one_call_api_validates_public_input_length() {
    let (doc, prompt, out) = real_witnesses();
    let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

    // Malformed payload (2 elements instead of 3) → the structured error,
    // distinguishable from a cryptographic rejection.
    let too_few = [doc, prompt];
    assert!(matches!(
        verify_proof(&proof, &too_few),
        Err(ZkpError::InvalidPublicInputs { len: 2 })
    ));
}

// ---------------------------------------------------------------------------
// 4. Provenance integrity — the proof binds the REAL evidence subgraph
// ---------------------------------------------------------------------------

#[test]
fn h_out_binds_the_exact_evidence_subgraph_bytes() {
    // The third public input must be the digest of EXACTLY the canonical
    // serialization of the evidence subgraph returned by find_path — the
    // same bytes the on-chain verifier will re-derive. This is the
    // cross-module provenance guarantee (graph.rs → zkp.rs) exercised
    // through the public API.
    let graph = evidence_graph();
    let path = graph.find_path("flare", "operates").expect("evidence");

    let canonical = serde_json::to_string(&path).expect("Path is serializable");
    let roundtrip: Path = serde_json::from_str(&canonical).expect("lossless round-trip");
    assert_eq!(
        roundtrip, path,
        "no evidence field may be dropped or reordered"
    );

    assert_eq!(
        graph_output_to_field(&path),
        digest_to_field(canonical.as_bytes()),
        "H_out must be the digest of exactly the canonical Path JSON"
    );

    // Byte-sensitivity: a different subgraph yields different bytes → a
    // different H_out → a proof for one can never verify for the other.
    let other = graph
        .find_path("flare", "no_such_predicate")
        .expect("anchor-only");
    assert_ne!(graph_output_to_field(&path), graph_output_to_field(&other));
}
