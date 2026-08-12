//! Integration tests — compile against the crate exactly as an external
//! consumer would (via `indexer_rs::`), proving the public API surface.
//!
//! These are *not* unit tests inside the module: they cannot reach private
//! fields, and any missing/renamed re-export fails to compile here. That is
//! the structural guarantee that the crate's root exports stay in sync with
//! the types the pipeline (Python enclave boundary) actually consumes.
//!
//! halo2 types (`Fp`, `EqAffine`, `Params`, keys) are imported from
//! `halo2_proofs` directly — exactly how an external consumer of the
//! circuit's public helpers must name them; `indexer_rs` deliberately does
//! not re-export the whole halo2 surface.

use indexer_rs::{
    digest_to_field, generate_params, generate_proof, graph_output_to_field, keygen, prove,
    prover_verifying_key, verify, verify_proof, Entity, EntityId, GraphError, KnowledgeGraph, Path,
    RAGConfig, RAGVerificationCircuit, Relation, ZkpError, DEFAULT_K,
};

use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{ProvingKey, VerifyingKey},
    poly::commitment::Params,
};

#[test]
fn public_surface_exposes_find_path_types() {
    // The return type of the public `find_path` query must be nameable at
    // the crate root — this file compiles only if `Path` is re-exported.
    fn name_path(_p: &Path) {}
    let _ = name_path as fn(&Path);

    let _ = std::any::type_name::<Entity>();
    let _ = std::any::type_name::<EntityId>();
    let _ = std::any::type_name::<GraphError>();
    let _ = std::any::type_name::<KnowledgeGraph>();
    let _ = std::any::type_name::<Relation>();
}

#[test]
fn public_surface_exposes_zkp_types() {
    // The ZKP circuit, its config, its error type, and the prover/verifier
    // helpers must all resolve at the crate root — this file compiles only
    // if every re-export is in sync with the exact halo2 0.3.5 signatures.
    fn name_circuit(_c: &RAGVerificationCircuit<Fp>) {}
    let _ = name_circuit as fn(&RAGVerificationCircuit<Fp>);
    let _ = std::any::type_name::<RAGConfig>();
    let _ = std::any::type_name::<ZkpError>();

    // The helper functions must be callable by name with the documented
    // signatures (Params at poly::commitment, keys at plonk — halo2 0.3.5).
    let _ = digest_to_field as fn(&[u8]) -> Fp;
    let _ = graph_output_to_field as fn(&Path) -> Fp;
    let _ = generate_params as fn(u32) -> Result<Params<EqAffine>, ZkpError>;
    let _ = keygen
        as fn(
            &Params<EqAffine>,
            &RAGVerificationCircuit<Fp>,
        ) -> Result<ProvingKey<EqAffine>, ZkpError>;
    let _ = prove
        as fn(
            &Params<EqAffine>,
            &ProvingKey<EqAffine>,
            &RAGVerificationCircuit<Fp>,
            &[Fp],
        ) -> Result<Vec<u8>, ZkpError>;
    let _ = verify
        as fn(&Params<EqAffine>, &VerifyingKey<EqAffine>, &[Fp], &[u8]) -> Result<(), ZkpError>;
    // Prompt 052: one-call proof generation with cached setup + companion
    // verifying-key accessor. The `Result` wrapper is the crate's structured-
    // error contract (never a bare `Vec<u8>` that would force a panic path).
    let _ = generate_proof as fn(Fp, Fp, Fp) -> Result<Vec<u8>, ZkpError>;
    let _ = prover_verifying_key as fn() -> &'static VerifyingKey<EqAffine>;
    // Prompt 053: one-call verification against the cached setup. Returns
    // Result (not the blueprint's bare bool) so rejected-vs-malformed stays
    // distinguishable — the crate's structured-error contract.
    let _ = verify_proof as fn(&[u8], &[Fp]) -> Result<(), ZkpError>;
    let _ = DEFAULT_K;
}

#[test]
fn find_path_is_callable_through_the_public_api() {
    let mut g = KnowledgeGraph::new();
    let a = g.add_entity("flare").expect("add");
    let b = g.add_entity("ftso").expect("add");
    g.add_relation(a, "operates", b).expect("add relation");

    let path = g
        .find_path("flare", "operates")
        .expect("subject exists in the graph");
    // The evidence subgraph is anchored on the query subject and carries
    // the exact predicate used for the traversal.
    assert_eq!(path.subject, a);
    assert_eq!(path.predicate, "operates");
    assert_eq!(path.entities, vec![a, b]);
    assert_eq!(path.depths, vec![0, 1]);
    assert_eq!(path.relations.len(), 1);
    assert_eq!(
        path.relations[0],
        Relation {
            subject: a,
            predicate: "operates".into(),
            object: b,
        }
    );
    assert_eq!(path.relation_depths, vec![0]);
}
