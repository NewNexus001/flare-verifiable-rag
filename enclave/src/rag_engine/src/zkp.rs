//! # halo2 ZKP circuit structures — `RAGVerificationCircuit`
//!
//! The zero-knowledge binding layer of the verifiable-RAG pipeline. Per the
//! architecture blueprint, the enclave produces a proof
//!
//! ```text
//! π = ZK-Prove( Circuit(H_doc, H_prompt, H_out) , w )
//! ```
//!
//! attesting that the prover held a witness consistent with three committed
//! public values: the **document state hash** `H_doc`, the **query predicate
//! hash** `H_prompt`, and the **symbolic graph output hash** `H_out` (the
//! SHA-256 of the serialized evidence subgraph produced by the deterministic
//! Rust knowledge engine).
//!
//! # What this proves (honest scope — expose & cross-check)
//!
//! Production verifiable-compute systems (zkML, Axiom-style coprocessors,
//! Chainlink Functions) **do not** enforce SHA-256 inside a PLONKish circuit:
//! a single SHA-256 costs ~20,000+ rows due to bitwise decomposition. The
//! established pattern is **expose & cross-check**: the circuit treats the
//! three hashes as witnesses, exposes all three as independent public inputs
//! via the instance column, and the on-chain verifier re-derives the hashes
//! from the submitted evidence (document, prompt, graph output) with cheap
//! native precompiles and asserts equality with the proof's public inputs.
//!
//! Concretely, this circuit proves: **"I hold witness values exactly equal to
//! these three public inputs"** — the equality/permutation binding via
//! `constrain_instance` (the canonical halo2 pattern, as used by the crate's
//! own `simple-example.rs`). It deliberately does **not** recompute any hash
//! inside the circuit (no `H_out = hash(H_doc, H_prompt)` gate), because that
//! relation is not the actual graph computation and faking it would be
//! dishonest. The deterministic graph traversal itself is executed by the
//! Rust engine (`KnowledgeGraph::find_path`) and its output hash is bound
//! here; the on-chain contract performs the authoritative cross-check.
//!
//! # Curve choice (documented divergence from the blueprint)
//!
//! The blueprint names the **BN254** pairing curve. The crate pinned in
//! `Cargo.toml` is `halo2_proofs 0.3.x` (the 2022-era Zcash line, chosen in
//! Prompt 042 for reproducibility), which ships **Pasta curves**
//! (`Fp`/`EqAffine`, Pallas/Vesta) — BN254 is **not available** in this
//! version. The circuit and helpers are therefore instantiated over the
//! Pasta scalar field `Fp`. Migrating to BN254 requires swapping to a
//! halo2 fork/`halo2curves` stack, updating `Cargo.toml`, and re-recording
//! the container digest — an explicit, deliberate change, never a silent
//! substitute.
//!
//! # Determinism & no-mock contract
//!
//! - **Deterministic:** identical witnesses + identical parameters produce
//!   an identical verified relation. `digest_to_field` maps arbitrary
//!   evidence bytes into a field element via SHA-256 + byte-wise base-256
//!   accumulation — pure, reproducible, zero randomness, zero mock data.
//! - **Real graph output:** `graph_output_to_field` hashes the *actual*
//!   serialized [`crate::Path`] evidence subgraph returned by
//!   [`crate::KnowledgeGraph::find_path`] — the pipeline is exercised end to
//!   end with real symbolic-engine output, never canned values.
//! - **Ephemeral:** zero I/O, zero disk; witnesses live only in memory.
//! - **Testable:** `MockProver` checks the binding, and a full keygen →
//!   prove → verify round-trip runs against real Halo commitment
//!   parameters (the scheme `halo2_proofs 0.3.x` actually ships — not KZG;
//!   see [`generate_params`]).

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof as halo2_verify_proof, Advice, Circuit,
        Column, ConstraintSystem, Error, Instance, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::Path;

/// Column layout for the [`RAGVerificationCircuit`].
///
/// One advice column holds `H_doc`, `H_prompt`, `H_out` at rows 0, 1, 2; one
/// instance column exposes the same three values as public inputs. Equality
/// is enabled on both so `constrain_instance` can bind the witnesses to the
/// public inputs via the permutation argument — the canonical halo2 pattern
/// (the crate's own `simple-example.rs` binds public inputs exactly this
/// way, with no custom gate).
#[derive(Clone, Debug)]
pub struct RAGConfig {
    /// Advice column: `H_doc` (row 0), `H_prompt` (row 1), `H_out` (row 2).
    advice: Column<Advice>,
    /// Instance (public input) column: same three values, rows 0–2.
    instance: Column<Instance>,
}

/// The verifiable-RAG binding circuit.
///
/// Public inputs (instance column, rows 0–2): `H_doc`, `H_prompt`, `H_out`.
/// The circuit binds all three witnesses to the public inputs via equality
/// constraints (expose & cross-check pattern — see module docs).
///
/// `F` is generic over `ff::Field` so the same structure is usable with any
/// halo2 field; the concrete helpers in this module use `Fp` (Pasta scalar
/// field), which is what `halo2_proofs 0.3` provides.
#[derive(Clone, Debug)]
pub struct RAGVerificationCircuit<F: Field> {
    /// Document-state hash `H_doc` (witness / public input).
    document_hash: Value<F>,
    /// Query-predicate hash `H_prompt` (witness / public input).
    prompt_hash: Value<F>,
    /// Symbolic graph output hash `H_out` — SHA-256 of the serialized
    /// evidence subgraph (witness / public input).
    graph_output_hash: Value<F>,
}

impl<F: Field> RAGVerificationCircuit<F> {
    /// A circuit with all witnesses unknown — used for key generation.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            document_hash: Value::unknown(),
            prompt_hash: Value::unknown(),
            graph_output_hash: Value::unknown(),
        }
    }

    /// A circuit with explicit witness values.
    #[must_use]
    pub fn new(
        document_hash: Value<F>,
        prompt_hash: Value<F>,
        graph_output_hash: Value<F>,
    ) -> Self {
        Self {
            document_hash,
            prompt_hash,
            graph_output_hash,
        }
    }

    /// A circuit with known (concrete) witness values.
    #[must_use]
    pub fn with_values(document_hash: F, prompt_hash: F, graph_output_hash: F) -> Self {
        Self::new(
            Value::known(document_hash),
            Value::known(prompt_hash),
            Value::known(graph_output_hash),
        )
    }
}

impl<F: Field> Circuit<F> for RAGVerificationCircuit<F> {
    type Config = RAGConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::unknown()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();

        // Equality enables the permutation/copy argument that
        // `constrain_instance` relies on to bind witnesses to public
        // inputs — the expose & cross-check binding (canonical halo2
        // pattern; no custom gate, no in-circuit hash computation).
        meta.enable_equality(advice);
        meta.enable_equality(instance);

        RAGConfig { advice, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let cells = layouter.assign_region(
            || "rag binding",
            |mut region| {
                let doc =
                    region.assign_advice(|| "H_doc", config.advice, 0, || self.document_hash)?;
                let prompt =
                    region.assign_advice(|| "H_prompt", config.advice, 1, || self.prompt_hash)?;
                let out = region.assign_advice(
                    || "H_out",
                    config.advice,
                    2,
                    || self.graph_output_hash,
                )?;
                Ok([doc, prompt, out])
            },
        )?;

        // Bind all three witnesses as public inputs (rows 0, 1, 2 of the
        // instance column) so the verifier can re-check them on-chain.
        layouter.constrain_instance(cells[0].cell(), config.instance, 0)?;
        layouter.constrain_instance(cells[1].cell(), config.instance, 1)?;
        layouter.constrain_instance(cells[2].cell(), config.instance, 2)?;

        Ok(())
    }
}

/// Deterministically maps arbitrary evidence bytes into a `Fp` field element.
///
/// SHA-256 the input, then interpret the 32 digest bytes as a **big-endian**
/// 256-bit integer (byte 0 is the **most** significant byte, weight 256^31;
/// byte 31 the least) and reduce it modulo `p` via Horner's method in base
/// 256 (`acc = acc * 256 + byte`, digest bytes consumed from index 0
/// upward — i.e. `digest.iter()`, so `digest[0]` ends up with the highest
/// weight).
///
/// Big-endian is deliberate: it is the same mapping Solidity applies with
/// `uint256(bytes32)`, so the on-chain cross-check re-derives identical
/// field elements from the same hash. The byte order is locked by an
/// independent big-integer oracle test (see
/// `digest_to_field_matches_independent_bigint_reference`), which caught an
/// earlier little-endian implementation that the determinism-only test
/// could not detect.
///
/// Pure function of the input — identical bytes always yield the identical
/// element, with no randomness and no mock data. This is how the pipeline
/// turns real document/prompt state into `H_doc` / `H_prompt` circuit
/// inputs.
///
/// # Field-reduction caveat (documented, per production guidance)
///
/// SHA-256 outputs 256 bits but the Pasta `Fp` modulus is ≈2^254.8, so a
/// 1:1 mapping is impossible. The byte-wise base-256 accumulation computes
/// the digest value modulo `p` deterministically. Because 2^256 is not a
/// perfect multiple of `p`, values in the lower range of the field have a
/// fractionally higher probability of occurring (a nominal modulo bias);
/// for a random-oracle output like SHA-256 this does not practically
/// compromise preimage or collision resistance, and the mapping is
/// identical on every machine and every run.
#[must_use]
pub fn digest_to_field(bytes: &[u8]) -> Fp {
    let digest = Sha256::digest(bytes);
    let mut acc = Fp::ZERO;
    // Big-endian interpretation: digest[0] is the most significant byte
    // (weight 256^31). Matches Solidity's `uint256(bytes32)` mapping so the
    // on-chain verifier derives the identical field element.
    for &byte in digest.iter() {
        acc = acc * Fp::from(256u64) + Fp::from(u64::from(byte));
    }
    acc
}

/// Computes the **symbolic graph output hash** `H_out` for a real evidence
/// subgraph.
///
/// The [`Path`] returned by [`crate::KnowledgeGraph::find_path`] is the
/// exact, deduplicated evidence subgraph the RAG engine extracted. It is
/// serialized to canonical JSON (serde round-trip) and hashed through
/// [`digest_to_field`]. This is the value bound as the third public input —
/// real symbolic-engine output, never a canned or stand-in value.
///
/// # Infallibility note (why no `Result`)
///
/// `serde_json::to_string` can only fail on non-string map keys, custom
/// serializer errors, or I/O errors. [`Path`] is a plain struct of `usize`,
/// `String` and `Vec` fields (no maps, no custom serializers) and the
/// output is an in-memory `Vec<u8>`, so serialization is **provably
/// infallible** for this type — the `.expect` cannot fire. The input is a
/// `&Path` already validated by the engine (not attacker bytes), so this
/// does not violate the crate's no-panic-on-untrusted-input contract.
#[must_use]
pub fn graph_output_to_field(path: &Path) -> Fp {
    let json = serde_json::to_string(path).expect("Path is serializable");
    digest_to_field(json.as_bytes())
}

/// Errors raised by the ZKP module's public helpers.
///
/// Only `Debug` + `Error` are derived: the `Halo2` variant wraps
/// `halo2_proofs::plonk::Error`, which is neither `Clone` nor `PartialEq`,
/// so equality on this type is not available by design.
#[derive(Debug, thiserror::Error)]
pub enum ZkpError {
    /// An unsupported `k` was requested for [`generate_params`].
    ///
    /// The underlying `Params::new` panics at `k >= 32` (its own `assert!`);
    /// this module never lets that raw assert surface on untrusted input —
    /// the no-panic contract of the crate. The upper bound is a practical
    /// resource ceiling: each increment of `k` doubles the parameter memory
    /// (`2^k` group elements, ~6 bytes each), so `k=31` would demand ~192 GB
    /// — a resource-exhaustion vector, not just a correctness boundary.
    /// `4..=24` covers every realistic RAG circuit with a sane footprint.
    #[error(
        "k={k} is out of range (supported: 4..=24; higher k demands 2^k group elements of RAM)"
    )]
    InvalidK { k: u32 },

    /// A malformed public-inputs slice was passed to [`prove`] or [`verify`].
    ///
    /// The circuit binds exactly three public inputs — `[H_doc, H_prompt,
    /// H_out]` — and this module validates that *before* reaching the halo2
    /// call, so a caller error surfaces as a structured error, never a
    /// deferred library error.
    #[error("public inputs must be exactly [H_doc, H_prompt, H_out] (3 elements), got {len}")]
    InvalidPublicInputs { len: usize },

    /// An error propagated from the halo2 proving stack.
    #[error("halo2 error: {0}")]
    Halo2(#[from] Error),
}

/// Generates the public parameters for the Pasta curve with `2^k` rows.
///
/// `halo2_proofs 0.3.x` implements the **Halo polynomial commitment scheme**
/// (eprint 2019/1021 — the module doc of `poly::commitment` states this
/// verbatim, and there is **no `kzg` module anywhere in the 0.3.5 source**).
/// KZG/Shplonk belongs to the PSE fork; labelling these parameters "KZG"
/// would be inaccurate, so the documentation says exactly what they are:
/// Halo IPA-style commitment parameters. `Params::new` derives them from a
/// fixed random-oracle transcript; for a production deployment the
/// parameters should come from a ceremony — noted, not silently skipped,
/// since this is testnet-stage scaffolding.
///
/// # Errors
///
/// Returns [`ZkpError::InvalidK`] for `k` outside `4..=24` — the underlying
/// `Params::new` would panic at `k >= 32` (its own `assert!`), and `k > 24`
/// demands impractically large parameter memory. This crate never lets a
/// library `assert!` surface as its public API contract.
pub fn generate_params(k: u32) -> Result<Params<EqAffine>, ZkpError> {
    if !(4..=24).contains(&k) {
        return Err(ZkpError::InvalidK { k });
    }
    Ok(Params::new(k))
}

/// Runs halo2 key generation for the circuit, returning the proving key
/// (the verifying key is reachable via [`ProvingKey::get_vk`]).
pub fn keygen(
    params: &Params<EqAffine>,
    circuit: &RAGVerificationCircuit<Fp>,
) -> Result<ProvingKey<EqAffine>, ZkpError> {
    let vk = keygen_vk(params, circuit)?;
    Ok(keygen_pk(params, vk, circuit)?)
}

/// Creates a real halo2 proof for the given circuit and public inputs.
///
/// Returns the serialized proof bytes (Blake2b transcript). `public_inputs`
/// must be exactly `[H_doc, H_prompt, H_out]` — three elements, one instance
/// column.
pub fn prove(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: &RAGVerificationCircuit<Fp>,
    public_inputs: &[Fp],
) -> Result<Vec<u8>, ZkpError> {
    if public_inputs.len() != 3 {
        return Err(ZkpError::InvalidPublicInputs {
            len: public_inputs.len(),
        });
    }
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        params,
        pk,
        std::slice::from_ref(circuit),
        &[&[public_inputs]],
        OsRng,
        &mut transcript,
    )?;
    Ok(transcript.finalize())
}

/// Verifies a halo2 proof against the verifying key and public inputs.
pub fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    public_inputs: &[Fp],
    proof: &[u8],
) -> Result<(), ZkpError> {
    if public_inputs.len() != 3 {
        return Err(ZkpError::InvalidPublicInputs {
            len: public_inputs.len(),
        });
    }
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    Ok(halo2_verify_proof(
        params,
        vk,
        strategy,
        &[&[public_inputs]],
        &mut transcript,
    )?)
}

// ---------------------------------------------------------------------------
// One-call proof generation (Prompt 052)
// ---------------------------------------------------------------------------

/// Default circuit size `k` (rows = `2^k`) for the cached prover setup.
///
/// Production guidance (Zcash halo2 book + Axiom/EZKL practice): a circuit
/// with 3 occupied rows needs at least `k = 4` (16 rows — 3 circuit rows
/// plus ~6 rows reserved for blinding factors injected by the zero-knowledge
/// machinery). `k = 8` (256 rows) is chosen here as the default: it leaves
/// 16× headroom for the circuit to grow (e.g. a future FDC/on-chain hash
/// gate) while keeping prover time in the sub-millisecond range and the
/// parameter memory footprint tiny (`2^k` group elements). This is a
/// deliberate, documented choice — not a magic number.
pub const DEFAULT_K: u32 = 8;

/// The lazily-initialized, process-wide prover setup: public parameters and
/// the proving key, built exactly once per process lifetime.
///
/// This is the production pattern your research confirmed (Axiom, EZKL,
/// Scroll): **separate setup from proving** — generate params + keygen once
/// at first use, then every `generate_proof` call strictly borrows the
/// cached pair. `Params::new(k)` is deterministic (hash-to-curve with a
/// fixed domain separator, no RNG — verified in the vendored 0.3.5 source),
/// and `keygen` is a pure function of params + circuit, so caching is safe
/// and byte-stable. `std::sync::OnceLock` is used (no external dependency;
/// `get_or_try_init` is stable since Rust 1.70, our floor is 1.85).
struct ProverSetup {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

static PROVER_SETUP: std::sync::OnceLock<ProverSetup> = std::sync::OnceLock::new();

/// Initializes (once) and returns the process-wide prover setup.
///
/// **Infallible by construction** — same documented reasoning as
/// [`graph_output_to_field`]'s serialization `expect`: `DEFAULT_K` is a
/// compile-time constant inside the supported `4..=24` range, so
/// [`generate_params`] cannot return `InvalidK`; and `keygen` on this fixed
/// circuit with valid params cannot fail (the existing test suite exercises
/// the identical keygen path repeatedly). [`generate_params`] keeps its
/// `Result` for callers passing *untrusted* `k`; the constant path here is
/// structurally safe, so `get_or_init` (stable) is used instead of the still-
/// unstable `get_or_try_init`.
fn prover_setup() -> &'static ProverSetup {
    PROVER_SETUP.get_or_init(|| {
        let params = generate_params(DEFAULT_K)
            .expect("DEFAULT_K is a const in 4..=24, so params generation cannot fail");
        let pk = keygen(&params, &RAGVerificationCircuit::<Fp>::unknown())
            .expect("keygen on the fixed circuit with valid params cannot fail");
        ProverSetup { params, pk }
    })
}

/// Generates a halo2 proof binding `doc_hash`, `prompt_hash` and `output`
/// as the three public inputs of the [`RAGVerificationCircuit`].
///
/// One-call convenience over [`generate_params`] + [`keygen`] + [`prove`]:
/// the setup (params + proving key) is cached process-wide after the first
/// call, and every subsequent call strictly reuses it (the production
/// setup/prove split). The three inputs are the field elements produced by
/// [`digest_to_field`] / [`graph_output_to_field`] — the real, deterministic
/// hashes of document state, query predicate and symbolic graph output.
///
/// **Honest note on the signature:** the blueprint sketches
/// `generate_proof(...) -> Vec<u8>`, but this crate returns
/// `Result<Vec<u8>, ZkpError>` so that every failure path (out-of-range `k`,
/// halo2 prover error) surfaces as a structured error — the crate's
/// no-panic-on-untrusted-input contract. The happy path is identical: a
/// `Vec<u8>` proof ready for the on-chain verifier.
///
/// # Proof randomization
///
/// Proofs are randomized: even for identical inputs, every call samples
/// fresh blinding factors (via `OsRng` inside `create_proof`), so the
/// returned bytes differ byte-for-byte across calls while remaining
/// verifiable against the same verifying key.
///
/// # Errors
///
/// **Only [`ZkpError::Halo2`] is reachable today** — a prover error from the
/// halo2 stack. The other variants are listed for completeness but are
/// structurally impossible here: [`ZkpError::InvalidPublicInputs`] cannot
/// fire because the public-input slice is a fixed 3-element array built in
/// this function, and [`ZkpError::InvalidK`] cannot fire because
/// `DEFAULT_K` is a compile-time constant inside `4..=24`.
pub fn generate_proof(doc_hash: Fp, prompt_hash: Fp, output: Fp) -> Result<Vec<u8>, ZkpError> {
    let setup = prover_setup();
    let circuit = RAGVerificationCircuit::with_values(doc_hash, prompt_hash, output);
    let public_inputs = [doc_hash, prompt_hash, output];
    prove(&setup.params, &setup.pk, &circuit, &public_inputs)
}

/// Returns the process-wide verifying key for the cached prover setup.
///
/// Companion to [`generate_proof`]: the verifying key is what a verifier
/// (the on-chain `VerifiableRAG.sol` contract in later phases, or a local
/// check) needs to validate proofs produced by this process. Derived from
/// the cached proving key, so it is guaranteed to match the proofs
/// [`generate_proof`] emits. Initializes the setup on first call.
///
/// # Cross-process / on-chain implication
///
/// This guarantee holds **within this process**; a verifier in another
/// process (the `VerifiableRAG.sol` contract in later phases) must receive
/// the *same* verifying-key bytes to accept these proofs. That is
/// achievable because the setup is deterministic — `Params::new(k)` is
/// hash-to-curve (no RNG, verified in the vendored 0.3.5 source) and
/// `keygen` is a pure function of params + circuit — so an identical vk can
/// be derived independently on any machine and registered on-chain. The
/// export/registration step belongs to the on-chain integration phase, not
/// here.
pub fn prover_verifying_key() -> &'static VerifyingKey<EqAffine> {
    prover_setup().pk.get_vk()
}

/// Verifies a halo2 proof against the process-wide cached setup, returning
/// `Ok(())` only for a cryptographically valid proof of the given public
/// inputs.
///
/// One-call convenience over [`verify`] using the cached params + verifying
/// key (the same setup [`generate_proof`] uses, so proofs produced by this
/// process verify here). Safe on attacker-controlled input: truncated or
/// corrupt `proof_bytes` return a structured [`ZkpError`] — never a panic
/// (the `Blake2bRead` transcript surfaces `UnexpectedEof`/invalid-point
/// errors cleanly; proven empirically by the fuzz-style tests below).
///
/// **Honest note on the signature:** the blueprint sketches
/// `verify_proof(...) -> bool`. This crate returns `Result<(), ZkpError>`
/// instead, for the same reason [`generate_proof`] returns `Result`:
/// collapsing every outcome to `bool` would **swallow the critical
/// distinction** between a cryptographically *rejected* proof (the math did
/// not hold — the caller should treat this as a hard denial) and a
/// *malformed* payload (wrong public-input length, truncated/ corrupt proof
/// bytes — a protocol/serialization bug or active fuzzing). An EVM verifier
/// may surface a `bool` (gas-optimized), but this Rust entrypoint keeps the
/// structured error; callers that want the EVM-style predicate use
/// `.is_ok()`.
///
/// # Errors
///
/// Returns [`ZkpError::InvalidPublicInputs`] if `public_inputs` is not
/// exactly 3 elements (`[H_doc, H_prompt, H_out]`), or a
/// [`ZkpError::Halo2`] error — `ConstraintSystemFailure` for a rejected
/// proof, `IoError` for truncated/corrupt proof bytes.
pub fn verify_proof(proof_bytes: &[u8], public_inputs: &[Fp]) -> Result<(), ZkpError> {
    let setup = prover_setup();
    verify(&setup.params, setup.pk.get_vk(), public_inputs, proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::KnowledgeGraph;

    /// The three public inputs for a bound witness, in instance order.
    fn public_inputs_for(doc: Fp, prompt: Fp, out: Fp) -> Vec<Fp> {
        vec![doc, prompt, out]
    }

    /// A small real knowledge graph with one predicate edge (diamond-free).
    fn evidence_graph() -> KnowledgeGraph {
        let mut g = KnowledgeGraph::new();
        let a = g.add_entity("flare").expect("add entity");
        let b = g.add_entity("ftso").expect("add entity");
        g.add_relation(a, "operates", b).expect("add relation");
        g
    }

    #[test]
    fn mock_prover_accepts_correct_binding() {
        let k = 4;
        let doc = Fp::from(3u64);
        let prompt = Fp::from(5u64);
        let out = Fp::from(7u64);
        let circuit = RAGVerificationCircuit::with_values(doc, prompt, out);

        let prover = halo2_proofs::dev::MockProver::run(
            k,
            &circuit,
            vec![public_inputs_for(doc, prompt, out)],
        )
        .expect("mock prover runs");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "matching witnesses and public inputs must satisfy the binding"
        );
    }

    #[test]
    fn mock_prover_rejects_mismatched_witness_and_public_input() {
        let k = 4;
        let doc = Fp::from(3u64);
        let prompt = Fp::from(5u64);
        let out = Fp::from(7u64);
        let circuit = RAGVerificationCircuit::with_values(doc, prompt, out);

        // Witnesses are correct, but the PUBLIC input differs — the
        // equality binding must fail.
        let prover = halo2_proofs::dev::MockProver::run(
            k,
            &circuit,
            vec![public_inputs_for(doc, prompt, out + Fp::ONE)],
        )
        .expect("mock prover runs");
        assert!(prover.verify().is_err(), "tampered public input must fail");
    }

    #[test]
    fn digest_to_field_matches_independent_bigint_reference() {
        // Independent reference oracle: interpret the digest as a big-endian
        // 256-bit integer (byte 0 = most significant) and reduce it modulo
        // the Pallas scalar-field modulus using num-bigint's general
        // big-integer division — a completely different code path from the
        // field's Horner accumulation. If the byte order is ever flipped by
        // a future refactor, this test fails while the self-consistency test
        // above would stay green — that is the point of an independent oracle.
        use ff::PrimeField;
        use num_bigint::BigUint;

        // The vendored `Fp::MODULUS` constant is a hex string with a `0x`
        // prefix (pasta_curves 0.5.2, fields/fp.rs) — parse it as hex.
        let modulus_hex = <Fp as PrimeField>::MODULUS.trim_start_matches("0x");
        let p = BigUint::parse_bytes(modulus_hex.as_bytes(), 16).expect("modulus is hex");
        for input in [
            b"".as_slice(),
            b"flare coston2 ftso",
            b"document: rwa insurance claim",
            b"the quick brown fox jumps over the lazy dog",
        ] {
            let digest = Sha256::digest(input);
            // Big-endian interpretation: digest[0] is the most significant byte.
            let n = BigUint::from_bytes_be(&digest);
            let r = n % &p;
            // Convert the reduced integer back to a field element via the
            // canonical little-endian Repr (pasta_curves: Repr = [u8; 32], LE).
            let bytes = r.to_bytes_le();
            let mut repr = [0u8; 32];
            repr[..bytes.len()].copy_from_slice(&bytes);
            let expected = Option::<Fp>::from(<Fp as PrimeField>::from_repr(repr))
                .expect("reduced value is canonical");
            assert_eq!(
                digest_to_field(input),
                expected,
                "big-int reference mismatch for input {input:?}"
            );
        }
    }

    #[test]
    fn digest_to_field_is_deterministic_and_input_sensitive() {
        let a = b"flare coston2 ftso";
        let b = b"flare coston2 ftsov2";

        let da = digest_to_field(a);
        assert_eq!(da, digest_to_field(a), "must be a pure function of input");
        assert_ne!(da, digest_to_field(b), "distinct evidence must differ");
        assert_ne!(digest_to_field(&[]), digest_to_field(a));
    }

    #[test]
    fn graph_output_to_field_hashes_real_evidence_subgraph() {
        let g = evidence_graph();
        let path = g
            .find_path("flare", "operates")
            .expect("subject exists in the graph");

        let h_out = graph_output_to_field(&path);
        // Deterministic: same evidence -> same hash.
        assert_eq!(h_out, graph_output_to_field(&path));
        // Distinct from the document/prompt hashes of the same graph.
        assert_ne!(h_out, digest_to_field(b"flare"));
        assert_ne!(h_out, digest_to_field(b"operates"));
    }

    #[test]
    fn evidence_bytes_fed_to_h_out_are_exactly_the_canonical_path_json() {
        // Cross-module integrity (graph.rs -> zkp.rs): H_out must be derived
        // from EXACTLY the canonical JSON of the find_path evidence subgraph
        // — byte-for-byte, with no extra framing, truncation, or dropped
        // fields. The on-chain verifier re-derives this hash from the
        // submitted evidence, so a silent mismatch here would break
        // settlement while the proof itself still verifies.
        use serde_json::Value;

        let g = evidence_graph();
        let path = g
            .find_path("flare", "operates")
            .expect("subject exists in the graph");

        // The graph module's serialization IS the byte string that reaches
        // SHA-256 inside graph_output_to_field.
        let canonical = serde_json::to_string(&path).expect("Path is serializable");
        assert_eq!(
            graph_output_to_field(&path),
            digest_to_field(canonical.as_bytes()),
            "H_out must be the digest of exactly the canonical Path JSON"
        );

        // The JSON round-trips losslessly: no evidence field is dropped or
        // reordered before hashing.
        let back: Path = serde_json::from_str(&canonical).expect("round-trip");
        assert_eq!(back, path);

        // The canonical form carries every field of the evidence subgraph.
        let v: Value = serde_json::from_str(&canonical).expect("valid json");
        assert!(v["subject"].is_u64() && v["predicate"].is_string());
        assert!(v["entities"].is_array() && v["depths"].is_array());
        assert!(v["relations"].is_array() && v["relation_depths"].is_array());

        // Byte-sensitivity: altering a single evidence value (a depth)
        // changes the canonical bytes and therefore H_out — the hash binds
        // every byte of the evidence subgraph.
        let mut tampered_v = v.clone();
        tampered_v["depths"][1] = Value::from(0u64); // 1 -> 0
        let tampered = serde_json::to_string(&tampered_v).expect("serialize");
        assert_ne!(tampered, canonical);
        assert_ne!(
            digest_to_field(tampered.as_bytes()),
            graph_output_to_field(&path)
        );

        // A different evidence subgraph yields different bytes -> different
        // H_out (anchor-only vs the full evidence).
        let other = g
            .find_path("flare", "no_such_predicate")
            .expect("anchor-only subgraph");
        assert_ne!(canonical, serde_json::to_string(&other).expect("serialize"));
        assert_ne!(graph_output_to_field(&path), graph_output_to_field(&other));
    }

    #[test]
    fn generate_params_rejects_out_of_range_k_without_panicking() {
        // The vendored Params::new asserts k < 32 (would panic). This module
        // must reject those inputs structurally instead. Params is not
        // PartialEq, so out-of-range inputs are asserted via `matches!`.
        assert!(matches!(
            generate_params(32),
            Err(ZkpError::InvalidK { k: 32 })
        ));
        assert!(matches!(
            generate_params(25),
            Err(ZkpError::InvalidK { k: 25 })
        ));
        assert!(matches!(
            generate_params(3),
            Err(ZkpError::InvalidK { k: 3 })
        ));
        assert!(matches!(
            generate_params(0),
            Err(ZkpError::InvalidK { k: 0 })
        ));
        // Only a small k is materialized: Params::new(k) allocates 2^k group
        // elements, so k=25 would demand ~400 MB and k=31 ~192 GB. The
        // boundary check itself is exercised with a modest k; the rejected
        // range is where the panic-avoidance contract lives.
        assert!(generate_params(4).is_ok());
        assert!(generate_params(10).is_ok());
    }

    #[test]
    fn prove_and_verify_reject_malformed_public_inputs() {
        let k = 4;
        let params = generate_params(k).expect("k=4 is supported");
        let doc = digest_to_field(b"document: malformed input test");
        let prompt = digest_to_field(b"prompt: input length contract");
        let out = digest_to_field(b"graph: evidence");
        let circuit = RAGVerificationCircuit::with_values(doc, prompt, out);
        let pk =
            keygen(&params, &RAGVerificationCircuit::<Fp>::unknown()).expect("keygen must succeed");

        // Wrong lengths must fail BEFORE reaching halo2, with the structured
        // error — not a deferred library error.
        let too_few = vec![doc, prompt];
        assert!(matches!(
            prove(&params, &pk, &circuit, &too_few),
            Err(ZkpError::InvalidPublicInputs { len: 2 })
        ));
        let too_many = vec![doc, prompt, out, out];
        assert!(matches!(
            prove(&params, &pk, &circuit, &too_many),
            Err(ZkpError::InvalidPublicInputs { len: 4 })
        ));
        // verify must enforce the same contract.
        assert!(matches!(
            verify(&params, pk.get_vk(), &too_few, b"proof"),
            Err(ZkpError::InvalidPublicInputs { len: 2 })
        ));
    }

    #[test]
    fn keygen_prove_verify_roundtrip_succeeds() {
        let k = 4;
        let params = generate_params(k).expect("k=4 is supported");

        // Real evidence-derived witnesses (no mock values): document and
        // prompt hashes plus the hash of an actual symbolic graph output.
        let doc = digest_to_field(b"document: flare network coverage");
        let prompt = digest_to_field(b"prompt: what is the FTSO v2 staleness bound?");
        let graph = evidence_graph();
        let path = graph.find_path("flare", "operates").expect("evidence");
        let out = graph_output_to_field(&path);
        let circuit = RAGVerificationCircuit::with_values(doc, prompt, out);
        let public_inputs = public_inputs_for(doc, prompt, out);

        // Keygen must run against the witness-free circuit.
        let pk =
            keygen(&params, &RAGVerificationCircuit::<Fp>::unknown()).expect("keygen must succeed");

        // Prove.
        let proof = prove(&params, &pk, &circuit, &public_inputs).expect("prove must succeed");
        assert!(
            !proof.is_empty(),
            "proof must be non-empty (real transcript output)"
        );

        // Verify.
        verify(&params, pk.get_vk(), &public_inputs, &proof).expect("honest proof must verify");
    }

    #[test]
    fn verification_rejects_tampered_public_input() {
        let k = 4;
        let params = generate_params(k).expect("k=4 is supported");
        let doc = digest_to_field(b"document: rwa insurance claim");
        let prompt = digest_to_field(b"prompt: payout condition");
        let graph = evidence_graph();
        let path = graph.find_path("flare", "operates").expect("evidence");
        let out = graph_output_to_field(&path);
        let circuit = RAGVerificationCircuit::with_values(doc, prompt, out);
        let honest = public_inputs_for(doc, prompt, out);

        let pk =
            keygen(&params, &RAGVerificationCircuit::<Fp>::unknown()).expect("keygen must succeed");
        let proof = prove(&params, &pk, &circuit, &honest).expect("prove must succeed");

        // Same proof, but the verifier is shown a tampered graph output hash.
        let tampered = public_inputs_for(doc, prompt, out + Fp::ONE);
        assert!(
            verify(&params, pk.get_vk(), &tampered, &proof).is_err(),
            "proof must not verify against altered public input"
        );
    }

    // ---------------------------------------------------------------------
    // Prompt 052 — one-call generate_proof
    // ---------------------------------------------------------------------

    /// Real evidence-derived witnesses, shared by the generate_proof tests.
    fn evidence_witnesses() -> (Fp, Fp, Fp) {
        let doc = digest_to_field(b"document: flare network coverage report");
        let prompt = digest_to_field(b"prompt: what is the FTSO v2 staleness bound?");
        let graph = evidence_graph();
        let path = graph.find_path("flare", "operates").expect("evidence");
        let out = graph_output_to_field(&path);
        (doc, prompt, out)
    }

    #[test]
    fn generate_proof_returns_real_non_empty_proof() {
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");
        assert!(
            !proof.is_empty(),
            "a real halo2 transcript must be non-empty (real proof bytes)"
        );
    }

    #[test]
    fn generate_proof_roundtrip_verifies_against_cached_vk() {
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

        // The companion accessor returns the SAME setup's verifying key, so
        // the proof must verify against it.
        let vk = prover_verifying_key();
        let setup = prover_setup();
        verify(&setup.params, vk, &[doc, prompt, out], &proof)
            .expect("proof generated by this process must verify");
    }

    #[test]
    fn generate_proof_rejects_tampered_public_input() {
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

        let vk = prover_verifying_key();
        let setup = prover_setup();
        // Same proof, tampered graph output hash — must fail.
        let tampered = [doc, prompt, out + Fp::ONE];
        assert!(
            verify(&setup.params, vk, &tampered, &proof).is_err(),
            "proof must not verify against altered public input"
        );
    }

    #[test]
    fn generate_proof_is_randomized_across_calls() {
        let (doc, prompt, out) = evidence_witnesses();
        let a = generate_proof(doc, prompt, out).expect("generate_proof must succeed");
        let b = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

        // Identical inputs, fresh blinding factors: proofs must differ
        // byte-for-byte (research-confirmed halo2 property) yet both verify.
        assert_ne!(
            a, b,
            "halo2 proofs are randomized: identical inputs must yield different bytes"
        );
        let vk = prover_verifying_key();
        let setup = prover_setup();
        let public_inputs = [doc, prompt, out];
        verify(&setup.params, vk, &public_inputs, &a).expect("first proof verifies");
        verify(&setup.params, vk, &public_inputs, &b).expect("second proof verifies");
    }

    #[test]
    fn verify_proof_accepts_honest_proof_roundtrip() {
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");
        let public_inputs = [doc, prompt, out];

        verify_proof(&proof, &public_inputs).expect("honest proof must verify");
    }

    #[test]
    fn verify_proof_rejects_tampered_public_input() {
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

        // Same proof, wrong graph output hash — the proof must be rejected.
        let tampered = [doc, prompt, out + Fp::ONE];
        assert!(
            verify_proof(&proof, &tampered).is_err(),
            "tampered public input must be rejected"
        );
    }

    #[test]
    fn verify_proof_rejects_wrong_public_input_length() {
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");

        // 2 elements instead of 3 — malformed payload, structured error,
        // distinguishable from a cryptographic rejection.
        let too_few = [doc, prompt];
        assert!(matches!(
            verify_proof(&proof, &too_few),
            Err(ZkpError::InvalidPublicInputs { len: 2 })
        ));
    }

    #[test]
    fn verify_proof_handles_attacker_truncated_proof_bytes_without_panicking() {
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");
        let public_inputs = [doc, prompt, out];

        // Fuzz-style: truncation at strategic points must return Err cleanly
        // — the Blake2b transcript surfaces UnexpectedEof without panicking
        // (research-confirmed; now empirically locked by this test). The
        // no-panic property is structural (transcript Read errors), not
        // cut-point-dependent, so sampling preserves the guarantee while
        // keeping the suite fast across the remaining build phases.
        let len = proof.len();
        for cut in [0usize, 1, len / 4, len / 2, 3 * len / 4, len - 1] {
            let truncated = &proof[..cut];
            assert!(
                verify_proof(truncated, &public_inputs).is_err(),
                "truncated proof at byte {cut} must be rejected cleanly, not panic"
            );
        }
    }

    #[test]
    fn verify_proof_handles_attacker_garbage_bytes_without_panicking() {
        let (doc, prompt, out) = evidence_witnesses();
        let public_inputs = [doc, prompt, out];

        // Fuzz-style: deterministic pseudo-random garbage of varying lengths
        // must all be rejected cleanly — no panic, no crash, just Err.
        let mut seed = 0x5EED_u64;
        for len in [1usize, 8, 32, 128, 512] {
            let garbage: Vec<u8> = (0..len)
                .map(|_| {
                    // xorshift — deterministic, no external rng dependency.
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed & 0xFF) as u8
                })
                .collect();
            assert!(
                verify_proof(&garbage, &public_inputs).is_err(),
                "garbage proof of {len} bytes must be rejected cleanly, not panic"
            );
        }
    }

    #[test]
    fn verify_proof_returns_bool_predicate_via_is_ok() {
        // The EVM-style bool predicate is one `.is_ok()` away, as documented.
        let (doc, prompt, out) = evidence_witnesses();
        let proof = generate_proof(doc, prompt, out).expect("generate_proof must succeed");
        let public_inputs = [doc, prompt, out];

        assert!(verify_proof(&proof, &public_inputs).is_ok());
        assert!(verify_proof(&proof, &[doc, prompt, out + Fp::ONE]).is_err());
        assert!(verify_proof(&[0u8; 32], &public_inputs).is_err());
    }

    #[test]
    fn prover_setup_is_cached_single_initialization() {
        // The OnceLock must initialize exactly once: repeated calls return
        // the same allocation (same address), and the cached pk's verifying
        // key is the same object as the accessor's.
        let s1 = prover_setup();
        let s2 = prover_setup();
        assert!(
            std::ptr::eq(s1, s2),
            "OnceLock must return the same setup allocation on every call"
        );
        let vk1 = prover_verifying_key();
        let vk2 = prover_verifying_key();
        assert!(
            std::ptr::eq(vk1, vk2),
            "verifying key accessor must return the same cached key"
        );
    }
}
