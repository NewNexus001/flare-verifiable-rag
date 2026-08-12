//! # PyO3 C-FFI bridge — Python enclave ⇄ Rust symbolic engine (Prompt 054)
//!
//! Exposes `parse_and_prove` (a `#[pyfunction]` — a private Rust item, so
//! referenced with backticks, not intra-doc links) to the Python FastAPI
//! enclave so the RAG gateway can submit a raw document + prompt and
//! receive a real halo2 proof binding the document hash, prompt hash and
//! symbolic-graph-output hash — with zero Python-side cryptographic work
//! and zero mock data.
//!
//! # Feature gating (the production pattern)
//!
//! This module compiles **only** with the `python` feature
//! (`cargo build --features python`). PyO3 is an *optional* dependency:
//! `pyo3 = { version = "0.29", optional = true }` and `python = ["dep:pyo3"]`
//! in `Cargo.toml`. Without the feature the crate builds and tests exactly
//! as before, pure Rust, no Python interpreter required. The
//! `extension-module` feature is deliberately **not** enabled: maturin ≥
//! 1.9.4 injects `PYO3_BUILD_EXTENSION_MODULE` itself when building the
//! wheel, and enabling it would break `cargo test` (no libpython linking).
//!
//! # GIL discipline (verified against vendored pyo3 0.29.2)
//!
//! halo2 uses `maybe-rayon` internally (the `multicore` feature), so the
//! proof generation **must not run while holding the GIL** — otherwise all
//! other Python threads in the enclave halt and worker threads risk
//! deadlock. pyo3 0.23+ renamed `allow_threads` → `Python::detach`
//! (confirmed present at `src/marker.rs:562` in 0.29.2; `allow_threads` is
//! gone). `parse_and_prove` therefore extracts the two `&str` inputs first,
//! then runs the entire deterministic pipeline inside `py.detach(...)`.

#![cfg(feature = "python")]

use crate::{digest_to_field, generate_proof, match_graph, parse, tokenize, DocumentAST, Pattern};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

/// The result of the deterministic pipeline: the proof bytes plus the three
/// 32-byte little-endian field-element representations of the commitments
/// the proof binds — the exact public inputs, so the Python enclave can
/// forward them for on-chain cross-checking.
type ProveResult = (Vec<u8>, [u8; 32], [u8; 32], [u8; 32]);

/// The deterministic core pipeline — pure Rust, GIL-free, testable.
///
/// 1. `tokenize` → `parse`: build the canonical AST from the raw document
///    (byte-exact, deterministic — no embeddings, no ML).
/// 2. `DocumentAST::from_ast`: extract the symbolic token graph.
/// 3. `match_graph`: evaluate a full-wildcard pattern against the graph to
///    obtain the matched evidence (the symbolic engine's output).
///
///    **Honest scope note:** the pattern is deliberately prompt-*independent*
///    at this phase — the evidence is the complete token-graph match, and the
///    prompt contributes only to `H_prompt`. A later phase wires the prompt
///    into the traversal (query parsing → subject/predicate/object pattern)
///    once the query engine lands; the docs and code must never disagree
///    about which is happening.
/// 4. Hash the three commitments: `H_doc = digest_to_field(document)`,
///    `H_prompt = digest_to_field(prompt)`, and
///    `H_out = digest_to_field(canonical_evidence_json)`.
/// 5. `generate_proof(H_doc, H_prompt, H_out)` against the cached setup.
///
/// Returns [`ProveResult`]: `(proof_bytes, doc_hash, prompt_hash,
/// output_hash)`.
///
/// # Errors
///
/// Every failure (unparseable document, empty graph, prover error) is
/// surfaced as a structured message — never a panic, never a fallback.
///
/// `String` (not the crate's `IndexerError`/`ZkpError`) is the error type at
/// this boundary deliberately: it is the last stop before Python, and a
/// `PyRuntimeError` with a human-readable message is the professional FFI
/// contract. The structured errors are converted at the call sites below.
fn parse_and_prove_core(document: &str, prompt: &str) -> Result<ProveResult, String> {
    use ff::PrimeField;

    // 1-2. Deterministic parse of the raw document.
    let tokens = tokenize(document).map_err(|e| e.to_string())?;
    let ast = parse(&tokens).map_err(|e| e.to_string())?;
    let graph = DocumentAST::from_ast(&ast);

    // 3. Symbolic matching: every edge of the token graph is evidence.
    //    A wildcard triple evaluates the full graph (subject / predicate /
    //    object all wildcards) — the deterministic engine output.
    let pattern = Pattern::single("*", "*", "*");
    let matches = match_graph(&graph, &pattern).map_err(|e| e.to_string())?;
    if matches.is_empty() {
        return Err("document produced no symbolic graph matches".to_string());
    }
    // Canonical, deterministic evidence serialization (BTreeMap ordering
    // and Vec order — no HashMap anywhere in this crate).
    let evidence_json = serde_json::to_vec(&matches).map_err(|e| e.to_string())?;

    // 4. Commitments. `content_digest` is the AST's canonical SHA-256 used
    //    for document identity; the three circuit inputs are the field
    //    elements the proof binds.
    let h_doc = digest_to_field(document.as_bytes());
    let h_prompt = digest_to_field(prompt.as_bytes());
    let h_out = digest_to_field(&evidence_json);

    // 5. Real halo2 proof via the cached process-wide setup.
    let proof = generate_proof(h_doc, h_prompt, h_out).map_err(|e| e.to_string())?;

    // Field elements → 32-byte little-endian representations (PrimeField).
    let doc_hash = h_doc.to_repr();
    let prompt_hash = h_prompt.to_repr();
    let output_hash = h_out.to_repr();

    Ok((proof, doc_hash, prompt_hash, output_hash))
}

/// Python-callable: `parse_and_prove(document: str, prompt: str) -> dict`
///
/// Returns a dict with `proof` (bytes), `doc_hash`, `prompt_hash`,
/// `output_hash` (32-byte little-endian field representations). Raises
/// `RuntimeError` with a structured message on any failure — never a panic.
#[pyfunction]
#[pyo3(signature = (document, prompt))]
// No explicit `text_signature`: with all-primitive required args, pyo3
// auto-generates the correct `help()` signature (the research-confirmed
// blind spot only affects non-primitive defaults, which we have none of).
fn parse_and_prove<'py>(
    py: Python<'py>,
    document: &str,
    prompt: &str,
) -> PyResult<Bound<'py, PyDict>> {
    // The whole pipeline — including halo2's rayon-backed prove — runs with
    // the GIL released so the Python enclave's other threads keep running
    // (verified: `Python::detach`, pyo3 0.29.2 marker.rs:562).
    let result = py.detach(|| parse_and_prove_core(document, prompt));
    let (proof, doc_hash, prompt_hash, output_hash) = result.map_err(PyRuntimeError::new_err)?;

    let dict = PyDict::new(py);
    dict.set_item("proof", PyBytes::new(py, &proof))?;
    dict.set_item("doc_hash", PyBytes::new(py, &doc_hash))?;
    dict.set_item("prompt_hash", PyBytes::new(py, &prompt_hash))?;
    dict.set_item("output_hash", PyBytes::new(py, &output_hash))?;
    Ok(dict)
}

/// The Python module: `import indexer_rs` exposes `parse_and_prove`.
#[pymodule]
fn indexer_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_and_prove, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::pasta::Fp;

    /// The pure-Rust core is testable without a Python interpreter — the
    /// deterministic pipeline + real proof + three matching public inputs.
    #[test]
    fn parse_and_prove_core_produces_verifiable_proof() {
        let document = "Flare operates FTSO v2. The oracle updates every block.";
        let prompt = "does flare operate ftso?";
        let (proof, doc_hash, prompt_hash, output_hash) =
            parse_and_prove_core(document, prompt).expect("pipeline must succeed");

        assert!(!proof.is_empty(), "real proof bytes required");

        // The returned hashes ARE the public inputs the proof binds — the
        // 32-byte representations round-trip through ff::PrimeField::from_repr
        // (the exact inverse of to_repr), and the proof must verify against
        // them with the same cached setup.
        use ff::PrimeField;
        let h_doc = Option::<Fp>::from(Fp::from_repr(doc_hash)).expect("doc_hash is canonical");
        let h_prompt =
            Option::<Fp>::from(Fp::from_repr(prompt_hash)).expect("prompt_hash is canonical");
        let h_out =
            Option::<Fp>::from(Fp::from_repr(output_hash)).expect("output_hash is canonical");
        let public_inputs = [h_doc, h_prompt, h_out];
        crate::verify_proof(&proof, &public_inputs).expect("proof must verify");
    }

    #[test]
    fn parse_and_prove_core_is_deterministic() {
        let document = "Flare operates FTSO v2.";
        let a = parse_and_prove_core(document, "prompt a").expect("pipeline a");
        let b = parse_and_prove_core(document, "prompt a").expect("pipeline b");

        // Proofs are randomized (blinding), but the three commitments must
        // be byte-identical — determinism of the symbolic pipeline.
        assert_eq!(a.1, b.1, "doc_hash must be deterministic");
        assert_eq!(a.2, b.2, "prompt_hash must be deterministic");
        assert_eq!(a.3, b.3, "output_hash must be deterministic");
        assert_ne!(a.0, b.0, "proofs are randomized by design");
    }

    #[test]
    fn parse_and_prove_core_errors_on_empty_document() {
        let err = parse_and_prove_core("", "prompt").expect_err("empty doc must fail");
        assert!(!err.is_empty(), "structured error message required");
    }
}
