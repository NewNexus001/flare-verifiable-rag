// enclave/enclave_grpc/src/attestation/eat_builder.rs
//
// Phase 12 (Prompts 223, 224) — IETF RATS EAT (RFC 9334) + COSE-Sign1
// (RFC 9052) construction.
//
// The enclave's hardware attestation is presented as an Entity Attestation
// Token: a CBOR claim set wrapped in a COSE_Sign1 envelope:
//
//   COSE_Sign1 = [ protected: bstr, unprotected: {}, payload: bstr,
//                  signature: bstr ]
//   Sig_structure = ["Signature1", protected, external_aad, payload]
//   signature = ES256(SHA-256(Sig_structure))   // ECDSA P-256, r||s (64B)
//
// Claims (RFC 9334 §3 / IANA EAT registry):
//   6   iat        issued-at (unix seconds)
//   10  nonce      eat_nonce (session-bound, echoed from the caller)
//   256 ueid       random-type UEID (0x02 || 16 random bytes)
//   266 submods    { "container": { swname, image_digest, hardware,
//                                   instance_id } }
//   342 swname     software name (e.g. "CONFIDENTIAL_SPACE")
//
// All crypto here is real: ES256 signatures over the exact Sig_structure
// bytes. The signing key is ephemeral and zeroized on drop (zeroize /
// ZeroizeOnDrop). Nothing is fabricated — the CLAIMS come from the caller
// (hardware report / build config), the CRYPTO is this module's.
#![allow(dead_code)]

use crate::attestation::tdx;
use crate::attestation::tdx::TeeDeviceError;
use ciborium::value::Value;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

// P231 — zeroize integration: the ephemeral attestation signing key must be
// scrubbed from memory the moment signing completes. This is guaranteed at
// the library level (ecdsa 0.16.9 implements `Drop` for `SigningKey` that
// zeroizes the secret scalar, and the `ZeroizeOnDrop` marker for it — both
// verified in the resolved crate source). The two assertions below make that
// guarantee a COMPILE-TIME CONTRACT of this crate: if a dependency upgrade
// ever silently drops the scrubbing, this code fails to build instead of
// shipping a key that lingers in RAM. Callers additionally scope the key so
// it is dropped immediately after build_eat returns (see grpc_server.rs).
fn _assert_signing_key_zeroizes_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SigningKey>();
}

// --- IANA EAT claim numbers (RFC 9334 §3.4 / registry) --------------------
pub const CLAIM_IAT: i128 = 6;
pub const CLAIM_NONCE: i128 = 10;
pub const CLAIM_UEID: i128 = 256;
pub const CLAIM_SUBMODS: i128 = 266;
pub const CLAIM_SWNAME: i128 = 342;

/// COSE algorithm ES256 (-7) per RFC 9053.
pub const ALG_ES256: i128 = -7;
pub const COSE_HEADER_ALG: i128 = 1;
pub const COSE_HEADER_KID: i128 = 4;

/// Default software name for the Confidential Space workload.
pub const DEFAULT_SWNAME: &str = "CONFIDENTIAL_SPACE";

/// EAT claims assembled from the hardware report + build configuration.
#[derive(Debug, Clone)]
pub struct EatClaims {
    /// Session nonce (echoed into eat_nonce; typically SHA-256 of the
    /// caller's nonce + reportdata).
    pub nonce: Vec<u8>,
    pub swname: String,
    /// Image digest (sha256:... of the enclave container).
    pub image_digest: String,
    pub hardware: String,
    pub instance_id: [u8; 16],
    /// Issued-at (unix seconds).
    pub iat: u64,
    /// TEE measurement registers (RTMRs / SNP measurements), optional.
    pub measurements: Vec<[u8; 32]>,
}

impl Default for EatClaims {
    fn default() -> Self {
        Self {
            nonce: Vec::new(),
            swname: DEFAULT_SWNAME.to_string(),
            image_digest: String::new(),
            hardware: "unknown".to_string(),
            instance_id: [0u8; 16],
            iat: 0,
            measurements: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum EatError {
    Cbor(ciborium::ser::Error<std::io::Error>),
    CborDe(ciborium::de::Error<std::io::Error>),
    Sign(p256::ecdsa::Error),
    Tee(TeeDeviceError),
    /// The claims must carry a non-empty image digest and swname.
    IncompleteClaims(&'static str),
    Malformed(&'static str),
}

impl std::fmt::Display for EatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EatError::Cbor(e) => write!(f, "cbor encode error: {e}"),
            EatError::CborDe(e) => write!(f, "cbor decode error: {e}"),
            EatError::Sign(e) => write!(f, "ES256 signing error: {e}"),
            EatError::Tee(e) => write!(f, "TEE error: {e}"),
            EatError::IncompleteClaims(msg) => write!(f, "incomplete claims: {msg}"),
            EatError::Malformed(msg) => write!(f, "malformed token: {msg}"),
        }
    }
}

impl std::error::Error for EatError {}

impl From<TeeDeviceError> for EatError {
    fn from(e: TeeDeviceError) -> Self {
        EatError::Tee(e)
    }
}

fn b(v: Vec<u8>) -> Value {
    Value::Bytes(v)
}

fn t(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn int(i: i128) -> Value {
    // ciborium's Integer implements From only for i8..i64/u8..u64.
    Value::Integer(ciborium::value::Integer::from(i as i64))
}

/// Encode the EAT claim set as a CBOR map.
pub fn encode_claims(claims: &EatClaims) -> Value {
    let mut map: Vec<(Value, Value)> = Vec::new();

    map.push((int(CLAIM_IAT), int(claims.iat as i128)));

    if !claims.nonce.is_empty() {
        map.push((int(CLAIM_NONCE), b(claims.nonce.clone())));
    }

    // Random-type UEID: 0x02 tag byte || 16 random bytes (RFC 9334 §4.2.4).
    let mut ueid = Vec::with_capacity(17);
    ueid.push(0x02);
    ueid.extend_from_slice(&claims.instance_id);
    map.push((int(CLAIM_UEID), b(ueid)));

    // swname is a TOP-LEVEL claim (RFC 9334 / IANA EAT registry) — the
    // verifier reads it there (Prompt 227 policy check).
    map.push((int(CLAIM_SWNAME), t(&claims.swname)));

    // submods: { "container": { "image_digest": …, "hardware": …,
    //                           "instance_id": …, rtmrN: … } }
    let mut container: Vec<(Value, Value)> = Vec::new();
    container.push((t("image_digest"), t(&claims.image_digest)));
    container.push((t("hardware"), t(&claims.hardware)));
    container.push((t("instance_id"), b(claims.instance_id.to_vec())));
    for (i, m) in claims.measurements.iter().enumerate() {
        container.push((t(&format!("rtmr{i}")), b(m.to_vec())));
    }
    let mut submods: Vec<(Value, Value)> = Vec::new();
    submods.push((t("container"), Value::Map(container)));
    map.push((int(CLAIM_SUBMODS), Value::Map(submods)));

    Value::Map(map)
}

/// Serialize any Value to CBOR bytes.
fn cbor(value: &Value) -> Result<Vec<u8>, EatError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(EatError::Cbor)?;
    Ok(out)
}

/// Build the COSE_Sign1 Sig_structure per RFC 9052 §4.4.
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Value {
    Value::Array(vec![
        t("Signature1"),
        b(protected.to_vec()),
        b(Vec::new()), // external_aad — empty
        b(payload.to_vec()),
    ])
}

/// Encode the EAT claims + COSE_Sign1 envelope, signed with `key`.
///
/// P231 contract: the signing key is never stored. It is created by the
/// caller immediately before this call, is dropped immediately after this
/// call returns, and is scrubbed on drop by the ecdsa crate's `Drop` impl
/// (compile-time asserted above via `ZeroizeOnDrop`). Nothing in this
/// function retains the key beyond the call frame.
pub fn build_eat(claims: &EatClaims, key: &SigningKey) -> Result<Vec<u8>, EatError> {
    if claims.swname.trim().is_empty() {
        return Err(EatError::IncompleteClaims("swname must not be empty"));
    }
    if claims.image_digest.trim().is_empty() {
        return Err(EatError::IncompleteClaims("image_digest must not be empty"));
    }

    // 1. Protected header: { 1: -7 (alg ES256), 4: kid }.
    let protected = Value::Map(vec![
        (int(COSE_HEADER_ALG), int(ALG_ES256)),
        (int(COSE_HEADER_KID), b(b"enclave-v1".to_vec())),
    ]);
    let protected_bytes = cbor(&protected)?;

    // 2. Payload: the EAT claim set.
    let payload_bytes = cbor(&encode_claims(claims))?;

    // 3. Signature over the exact Sig_structure bytes.
    let sig_input = cbor(&sig_structure(&protected_bytes, &payload_bytes))?;
    // Signer::sign returns the Signature directly (no Result) — ES256 r||s.
    let signature: Signature = key.sign(&sig_input);
    let signature_bytes = signature.to_bytes();
    // Deref to a byte slice (avoids the deprecated GenericArray::as_slice).
    let sig_slice: &[u8] = &signature_bytes;
    let signature_vec: Vec<u8> = sig_slice.to_vec();

    // 4. COSE_Sign1 array.
    let cose = Value::Array(vec![
        b(protected_bytes),
        Value::Map(Vec::new()), // unprotected — empty
        b(payload_bytes),
        b(signature_vec),
    ]);

    cbor(&cose)
}

/// Parsed view of a COSE_Sign1 token.
#[derive(Debug, Clone)]
pub struct ParsedCoseSign1 {
    pub protected: Vec<u8>,
    pub protected_map: Value,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Parse a COSE_Sign1 byte string into its parts (RFC 9052 §4.2).
pub fn parse_cose_sign1(token: &[u8]) -> Result<ParsedCoseSign1, EatError> {
    let value: Value = ciborium::de::from_reader(token).map_err(EatError::CborDe)?;
    let parts = match value {
        Value::Array(parts) if parts.len() == 4 => parts,
        _ => return Err(EatError::Malformed("COSE_Sign1 must be an array of 4 elements")),
    };
    let protected = match &parts[0] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(EatError::Malformed("protected must be a bstr")),
    };
    let protected_map: Value =
        ciborium::de::from_reader(&protected[..]).map_err(EatError::CborDe)?;
    let payload = match &parts[2] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(EatError::Malformed("payload must be a bstr")),
    };
    let signature = match &parts[3] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(EatError::Malformed("signature must be a bstr")),
    };
    Ok(ParsedCoseSign1 {
        protected,
        protected_map,
        payload,
        signature,
    })
}

/// Extract the EAT claim set from a payload (returns the CBOR map value).
pub fn decode_claims(payload: &[u8]) -> Result<Value, EatError> {
    ciborium::de::from_reader(payload).map_err(EatError::CborDe)
}

/// A minimal nonce → reportdata binding: SHA-256 of the caller nonce.
pub fn nonce_to_reportdata(nonce: &[u8]) -> [u8; tdx::TDX_REPORTDATA_LEN] {
    let mut out = [0u8; tdx::TDX_REPORTDATA_LEN];
    let digest = Sha256::digest(nonce);
    out[..digest.len()].copy_from_slice(&digest);
    out
}
