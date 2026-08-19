// enclave/enclave_grpc/tests/test_eat_builder.rs
//
// Phase 12 (Prompt 225) — EAT token serialization + CBOR parsing tests.
//
// Covers the full RFC 9334 / RFC 9052 lifecycle with real ES256 crypto:
//   - COSE_Sign1 shape (4 elements, ES256 in protected header)
//   - signature verifies against the exact Sig_structure
//   - tampering (byte flip in the signature) is detected
//   - a different signing key is rejected
//   - policy checks reject wrong swname / image digest
//   - incomplete claims are rejected before signing
use enclave_grpc::attestation::eat_builder::{
    build_eat, parse_cose_sign1, ALG_ES256, COSE_HEADER_ALG, DEFAULT_SWNAME, EatClaims, EatError,
};
use enclave_grpc::attestation::verifier::{
    validate_claims, verify_cose_sign1, EatVerifyError,
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;

const DIGEST: &str =
    "sha256:8a1a98fa247bc0895b40ec16e89de96f0d935bd5be11bde02744f373ef207d6e";

fn claims() -> EatClaims {
    EatClaims {
        nonce: b"nonce-123".to_vec(),
        swname: DEFAULT_SWNAME.to_string(),
        image_digest: DIGEST.to_string(),
        hardware: "intel-tdx".to_string(),
        instance_id: [7u8; 16],
        iat: 1_700_000_000,
        measurements: vec![[0xAB; 32]],
    }
}

fn build_token() -> (Vec<u8>, SigningKey) {
    let key = SigningKey::random(&mut OsRng);
    let token = build_eat(&claims(), &key).unwrap();
    (token, key)
}

#[test]
fn cose_sign1_structure_and_es256_header() {
    let (token, _key) = build_token();
    let parsed = parse_cose_sign1(&token).unwrap();

    // Protected header declares alg = ES256 (-7) + a kid.
    let entries = match parsed.protected_map {
        ciborium::value::Value::Map(entries) => entries,
        _ => panic!("protected header must be a CBOR map"),
    };
    let alg = entries
        .iter()
        .find(|(k, _)| {
            matches!(
                k,
                ciborium::value::Value::Integer(i)
                    if *i == ciborium::value::Integer::from(COSE_HEADER_ALG as i64)
            )
        })
        .expect("alg header present");
    // alg value must be ES256 (-7) — compare via i128 (From<Integer>).
    // (alg.1 is a place of owned Value; v binds by value.)
    let alg_val: i128 = match alg.1 {
        ciborium::value::Value::Integer(v) => v.into(),
        _ => panic!("alg must be a CBOR integer"),
    };
    assert_eq!(alg_val, ALG_ES256);

    // ES256 signature is 64 bytes r||s (RFC 9053), not DER.
    assert_eq!(parsed.signature.len(), 64);
    assert!(!parsed.payload.is_empty());
}

#[test]
fn signature_verifies_against_sig_structure() {
    let (token, key) = build_token();
    let vk = VerifyingKey::from(&key);
    let payload = verify_cose_sign1(&token, &vk).expect("signature must verify");
    assert!(!payload.is_empty());
}

#[test]
fn tampered_token_is_rejected() {
    let (mut token, key) = build_token();
    let vk = VerifyingKey::from(&key);

    // Flip the LAST byte (inside the 64-byte signature) — verification must
    // fail, proving the signature covers the exact token bytes.
    let last = token.len() - 1;
    token[last] ^= 0xFF;

    let res = verify_cose_sign1(&token, &vk);
    assert!(
        matches!(res, Err(EatVerifyError::BadSignature(_))),
        "tampered signature must be rejected, got {res:?}"
    );
}

#[test]
fn wrong_signing_key_is_rejected() {
    let (token, _key) = build_token();
    let other = SigningKey::random(&mut OsRng);
    let other_vk = VerifyingKey::from(&other);
    let res = verify_cose_sign1(&token, &other_vk);
    assert!(matches!(res, Err(EatVerifyError::BadSignature(_))));
}

#[test]
fn policy_rejects_wrong_swname_and_digest() {
    let (token, key) = build_token();
    let vk = VerifyingKey::from(&key);
    let payload = verify_cose_sign1(&token, &vk).unwrap();

    // Wrong swname.
    let res = validate_claims(&payload, "NOT_CONFIDENTIAL", None, None);
    assert!(matches!(res, Err(EatVerifyError::Policy(_))));

    // Wrong image digest (build digest mismatch — Prompt 227).
    let res = validate_claims(&payload, DEFAULT_SWNAME, Some("sha256:deadbeef"), None);
    assert!(matches!(res, Err(EatVerifyError::Policy(_))));

    // Wrong nonce (session binding).
    let res = validate_claims(&payload, DEFAULT_SWNAME, Some(DIGEST), Some(b"other-nonce"));
    assert!(matches!(res, Err(EatVerifyError::Policy(_))));
}

#[test]
fn policy_accepts_matching_claims() {
    let (token, key) = build_token();
    let vk = VerifyingKey::from(&key);
    let payload = verify_cose_sign1(&token, &vk).unwrap();
    let verified = validate_claims(&payload, DEFAULT_SWNAME, Some(DIGEST), Some(b"nonce-123"))
        .expect("matching claims must verify");
    assert_eq!(verified.image_digest, DIGEST);
    assert_eq!(verified.swname, DEFAULT_SWNAME);
}

#[test]
fn incomplete_claims_are_rejected_before_signing() {
    let key = SigningKey::random(&mut OsRng);
    let mut c = claims();
    c.image_digest = String::new();
    let res = build_eat(&c, &key);
    assert!(matches!(res, Err(EatError::IncompleteClaims(_))));

    let mut c2 = claims();
    c2.swname = "   ".to_string();
    let res2 = build_eat(&c2, &key);
    assert!(matches!(res2, Err(EatError::IncompleteClaims(_))));
}
