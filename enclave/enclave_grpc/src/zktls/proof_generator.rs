// enclave/enclave_grpc/src/zktls/proof_generator.rs
//
// Phase 14 (Prompts 264-265, 278) — cryptographic zkTLS proof generation.
//
// The proof attests: "the enclave opened a validated TLS 1.3 session to
// <url>, the server presented certificate chain <fingerprint>, the response
// body hashes to <response_hash>, and running jq selector <selector> over
// the decrypted payload produced <selected data> (data_hash)."
//
// jq evaluation (Prompt 265) uses jaq-all — the professional jq engine for
// Rust (jaq-core + jaq-std + jaq-json). This is the SAME jq semantics the
// Flare FDC attestor network runs for Web2Json `postProcessJq` filters
// (verified against the repo's own FDC script: request_fdc_attestation.ts
// uses `postProcessJq: ".completed"`). We never hand-roll a "subset": the
// full jq language compiles and runs here.
//
// The signature (Prompt 264) is secp256k1 ECDSA (k256 — the same curve the
// Phase 13 MPC wallet uses) over keccak256 of a canonical proof payload.
// ecrecover-compatible: the on-chain verifier (ZkTlsRelayer.sol) recomputes
// the same digest and recovers the enclave identity address — identical math
// to IKmsVerifiedWallet.requireKmsSignature.
//
// Prompt 278 (header redaction): the proof payload is constructed ONLY from
// url, selector, selected data, response hash, cert fingerprint, nonce and
// timestamp. Request headers (Authorization/Bearer) are consumed by the
// proxy's request and are structurally absent here — `redacted_for_proof`
// asserts the payload contains none of the request's header values.

use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
// sha2::Digest and sha3::Digest are the SAME trait (both re-export the
// `digest` crate's Digest) — one import serves both hashers.
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use super::cert_verifier::CapturedChain;

/// Protocol version byte for the signed payload (domain separation).
pub const PROOF_VERSION: u8 = 1;

/// An error while evaluating jq or building a proof.
#[derive(Debug)]
pub enum ProofError {
    /// The response body is not valid JSON.
    InvalidJson(String),
    /// The jq filter failed to compile (syntax/type error).
    JqCompile(String),
    /// jq produced no output for the selector (empty selection).
    EmptySelection(String),
    /// A proof/signature could not be built.
    Build(String),
    /// The serialized proof is malformed.
    Decode(String),
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofError::InvalidJson(e) => write!(f, "response is not valid JSON: {e}"),
            ProofError::JqCompile(e) => write!(f, "jq filter failed to compile: {e}"),
            ProofError::EmptySelection(s) => write!(f, "jq selector produced no output: {s}"),
            ProofError::Build(e) => write!(f, "proof build failed: {e}"),
            ProofError::Decode(e) => write!(f, "proof decode failed: {e}"),
        }
    }
}

impl std::error::Error for ProofError {}

/// Run a jq selector over a JSON payload and return the concatenated,
/// serialized outputs — the same semantics as the FDC's postProcessJq
/// (jaq-all's own high-level API: compile → parse → run → write).
pub fn jq_select(json: &[u8], selector: &str) -> Result<Vec<u8>, ProofError> {
    let filter = jaq_all::data::compile(selector).map_err(|reports| {
        let msgs: Vec<String> = reports
            .iter()
            .map(|r| format!("{}", jaq_all::load::FileReportsDisp::new(r)))
            .collect();
        ProofError::JqCompile(msgs.join("; "))
    })?;

    let inputs = jaq_all::fmts::read::json::parse_many(json);
    let runner = jaq_all::data::Runner::default();
    // Vars is crate-private in jaq-all 0.3; Default::default() is the
    // documented construction (the official example does exactly this).
    let vars = Default::default();

    let mut out: Vec<u8> = Vec::new();
    let mut wrote = false;
    let fi = |e: String| ProofError::Build(e);
    // The input iterator yields Result<Val, Error>; jaq-all's `run` takes
    // `impl Iterator<Item = Result<Val, impl ToString>>` — map the parse
    // error to a string so the typed error survives.
    let inputs = inputs.map(|r| r.map_err(|e| e.to_string()));
    jaq_all::data::run(
        &runner,
        &filter,
        vars,
        inputs,
        fi,
        |v| {
            let v = jaq_all::jaq_core::unwrap_valr(v)
                .map_err(|e| ProofError::Build(e.to_string()))?;
            // Serialize like jq's output writer (compact by default; the
            // writer itself emits the trailing newline per output, exactly
            // like `jq`).
            let mut buf: Vec<u8> = Vec::new();
            jaq_all::fmts::write::write(&mut buf, &runner.writer, &v)
                .map_err(|e| ProofError::Build(e.to_string()))?;
            out.extend_from_slice(&buf);
            wrote = true;
            Ok(())
        },
    )
    .map_err(|e| ProofError::Build(format!("jq run failed: {e}")))?;

    if !wrote {
        return Err(ProofError::EmptySelection(selector.to_string()));
    }
    Ok(out)
}

/// sha256 of a byte slice.
pub fn sha256_of(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// keccak256 (Ethereum) of a byte slice.
pub fn keccak256_of(data: &[u8]) -> [u8; 32] {
    let d = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// The canonical proof payload that gets signed (and recomputed on-chain):
///   version || url_hash || data_hash || response_hash || cert_fingerprint
///   || timestamp(8 BE) || nonce(16)
/// The on-chain contract must reproduce this EXACT byte layout with
/// abi.encodePacked to recover the signer (see ZkTlsRelayer.sol).
pub fn canonical_payload(
    version: u8,
    url_hash: &[u8; 32],
    data_hash: &[u8; 32],
    response_hash: &[u8; 32],
    cert_fingerprint: &[u8; 32],
    timestamp: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 32 + 32 + 32 + 32 + 8 + 16);
    payload.push(version);
    payload.extend_from_slice(url_hash);
    payload.extend_from_slice(data_hash);
    payload.extend_from_slice(response_hash);
    payload.extend_from_slice(cert_fingerprint);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(nonce);
    payload
}

/// A complete zkTLS proof: the signed binding of (url, selector, selected
/// data, response, cert chain) plus the ECDSA signature over it.
#[derive(Debug, Clone)]
pub struct ZkTlsProof {
    pub version: u8,
    pub url_hash: [u8; 32],
    pub data_hash: [u8; 32],
    pub response_hash: [u8; 32],
    pub cert_fingerprint: [u8; 32],
    pub timestamp: u64,
    pub nonce: [u8; 16],
    /// ECDSA signature: r || s (32+32) and recovery byte v (0 or 1).
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl ZkTlsProof {
    /// Serialize to the canonical wire format:
    ///   version(1) || url_hash(32) || data_hash(32) || response_hash(32) ||
    ///   cert_fingerprint(32) || timestamp(8 BE) || nonce(16) ||
    ///   r(32) || s(32) || v(1)
    /// This exact layout is what ZkTlsRelayer.sol decodes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 * 4 + 8 + 16 + 65);
        out.push(self.version);
        out.extend_from_slice(&self.url_hash);
        out.extend_from_slice(&self.data_hash);
        out.extend_from_slice(&self.response_hash);
        out.extend_from_slice(&self.cert_fingerprint);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.r);
        out.extend_from_slice(&self.s);
        out.push(self.v);
        out
    }

    /// Parse from the canonical wire format ({to_bytes}).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        const HDR: usize = 1 + 32 * 4 + 8 + 16; // header before r
        if bytes.len() != HDR + 32 + 32 + 1 {
            return Err(ProofError::Decode(format!(
                "expected {} bytes, got {}",
                HDR + 65,
                bytes.len()
            )));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[HDR..HDR + 32]);
        s.copy_from_slice(&bytes[HDR + 32..HDR + 64]);
        let mut url_hash = [0u8; 32];
        let mut data_hash = [0u8; 32];
        let mut response_hash = [0u8; 32];
        let mut cert_fingerprint = [0u8; 32];
        url_hash.copy_from_slice(&bytes[1..33]);
        data_hash.copy_from_slice(&bytes[33..65]);
        response_hash.copy_from_slice(&bytes[65..97]);
        cert_fingerprint.copy_from_slice(&bytes[97..129]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[129..137]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[137..153]);
        Ok(Self {
            version: bytes[0],
            url_hash,
            data_hash,
            response_hash,
            cert_fingerprint,
            timestamp: u64::from_be_bytes(ts),
            nonce,
            r,
            s,
            v: bytes[HDR + 64],
        })
    }

    /// The digest that was signed = keccak256(canonical_payload(...)) —
    /// exactly what the on-chain ecrecover recomputes.
    pub fn signed_digest(&self) -> [u8; 32] {
        let payload = canonical_payload(
            self.version,
            &self.url_hash,
            &self.data_hash,
            &self.response_hash,
            &self.cert_fingerprint,
            self.timestamp,
            &self.nonce,
        );
        keccak256_of(&payload)
    }

    /// Recover the signing address (secp256k1 public key → Ethereum address).
    ///
    /// recover_from_digest FINALIZES the passed hasher to get the 32-byte
    /// message hash — so the hasher must be built over the PAYLOAD (the
    /// same preimage `generate_proof` signed), never over the already-hashed
    /// digest (that would double-hash). Mirrors the proven Phase 13
    /// mpc_signer recovery pattern.
    pub fn recover_signer(&self) -> Result<[u8; 20], ProofError> {
        let payload = canonical_payload(
            self.version,
            &self.url_hash,
            &self.data_hash,
            &self.response_hash,
            &self.cert_fingerprint,
            self.timestamp,
            &self.nonce,
        );
        let recid = RecoveryId::try_from(self.v).map_err(|_| ProofError::Decode("bad v".into()))?;
        // r || s (64 bytes) — the standard Signature wire form.
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&self.r);
        rs[32..].copy_from_slice(&self.s);
        let sig = Signature::from_slice(&rs).map_err(|e| ProofError::Decode(e.to_string()))?;
        let vk =
            VerifyingKey::recover_from_digest(Keccak256::new_with_prefix(payload), &sig, recid)
                .map_err(|e| ProofError::Decode(e.to_string()))?;
        let uncompressed = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Ok(addr)
    }
}

/// Cert chain fingerprint: sha256 over the concatenated DER of the presented
/// chain (end-entity first) — binds the exact chain the handshake presented.
pub fn cert_fingerprint(chain: &CapturedChain) -> [u8; 32] {
    let mut all = Vec::new();
    for der in chain.all_der() {
        all.extend_from_slice(&der);
    }
    sha256_of(&all)
}

/// Build a zkTLS proof.
///
/// `signer` is the enclave identity key (secp256k1, the same family as the
/// Phase 13 MPC wallet). `nonce` is supplied by the caller (16 random bytes
/// — the enclave mints it from OsRng in the caller; kept as a parameter so
/// the caller controls freshness/rotation).
///
/// Prompt 278 enforcement: only url/selector/data/response/cert enter the
/// payload. `redact` (if Some) is checked against the serialized proof — if
/// any of those request-header values appear, the build fails. This makes
/// the guarantee mechanical, not aspirational.
pub fn generate_proof(
    url: &str,
    response_body: &[u8],
    selector: &str,
    chain: &CapturedChain,
    signer: &SigningKey,
    nonce: [u8; 16],
    redact: Option<&[&str]>,
) -> Result<ZkTlsProof, ProofError> {
    // 1) jq evaluation over the decrypted payload (Prompt 265).
    let selected = jq_select(response_body, selector)?;

    // 2) Hashes.
    let url_hash = sha256_of(url.as_bytes());
    let data_hash = sha256_of(&selected);
    let response_hash = sha256_of(response_body);
    let fingerprint = cert_fingerprint(chain);

    // 3) Timestamp (wall clock, seconds).
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ProofError::Build(e.to_string()))?
        .as_secs();

    // 4) Sign the canonical payload with the enclave identity key.
    let payload = canonical_payload(
        PROOF_VERSION,
        &url_hash,
        &data_hash,
        &response_hash,
        &fingerprint,
        timestamp,
        &nonce,
    );
    let digest = Keccak256::new_with_prefix(&payload);
    let (signature, recovery_id) = signer
        .sign_digest_recoverable(digest)
        .map_err(|e| ProofError::Build(e.to_string()))?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let (r_bytes, s_bytes) = signature.split_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);

    let proof = ZkTlsProof {
        version: PROOF_VERSION,
        url_hash,
        data_hash,
        response_hash,
        cert_fingerprint: fingerprint,
        timestamp,
        nonce,
        r,
        s,
        v: recovery_id.to_byte(),
    };

    // 5) Prompt 278: assert request-header values never leaked into the proof.
    if let Some(secrets) = redact {
        let serialized = proof.to_bytes();
        for secret in secrets {
            if serialized
                .windows(secret.as_bytes().len())
                .any(|w| w == secret.as_bytes())
            {
                return Err(ProofError::Build(format!(
                    "request header value leaked into proof payload"
                )));
            }
        }
    }

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey as KSigningKey;
    use k256::elliptic_curve::rand_core::OsRng;

    fn test_chain() -> CapturedChain {
        CapturedChain {
            server: "api.example".into(),
            end_entity: vec![0x30, 0x01, 0xAA],
            intermediates: vec![vec![0x30, 0x01, 0xBB]],
        }
    }

    #[test]
    fn jq_select_extracts_dot_path() {
        let json = br#"{"completed":true,"todos":[{"title":"buy milk","id":1}]}"#;
        let out = jq_select(json, ".todos[0].title").expect("jq runs");
        assert_eq!(out, b"\"buy milk\"\n");
    }

    #[test]
    fn jq_select_rejects_invalid_filter() {
        let json = br#"{"a":1}"#;
        let err = jq_select(json, ".a[").unwrap_err();
        assert!(matches!(err, ProofError::JqCompile(_)));
    }

    #[test]
    fn jq_select_empty_selection_errors() {
        // jq semantics: `.b` on a missing key emits `null` (NOT empty) — so
        // the genuinely empty-producing filter `empty` is the right probe.
        let json = br#"{"a":1}"#;
        let err = jq_select(json, "empty").unwrap_err();
        assert!(matches!(err, ProofError::EmptySelection(_)));
        // And `.b` correctly yields the jq `null` output, proving we run
        // REAL jq semantics (a hand-rolled subset would likely error here).
        assert_eq!(jq_select(json, ".b").expect("null output"), b"null\n");
    }

    #[test]
    fn proof_roundtrip_and_signer_recovery() {
        let sk = KSigningKey::random(&mut OsRng);
        let chain = test_chain();
        let nonce = [7u8; 16];
        let proof = generate_proof(
            "https://api.example/data",
            br#"{"completed":true}"#,
            ".completed",
            &chain,
            &sk,
            nonce,
            None,
        )
        .expect("proof builds");
        let bytes = proof.to_bytes();
        let decoded = ZkTlsProof::from_bytes(&bytes).expect("decodes");
        assert_eq!(decoded.version, PROOF_VERSION);
        assert_eq!(decoded.url_hash, proof.url_hash);
        assert_eq!(decoded.data_hash, proof.data_hash);
        assert_eq!(decoded.nonce, nonce);

        // Recover the signer address from the signature.
        let recovered = decoded.recover_signer().expect("recovers");
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..]);
        assert_eq!(recovered, expected);
    }

    #[test]
    fn proof_rejects_tampered_hash() {
        let sk = KSigningKey::random(&mut OsRng);
        let chain = test_chain();
        let proof = generate_proof(
            "https://api.example/data",
            br#"{"completed":true}"#,
            ".completed",
            &chain,
            &sk,
            [1u8; 16],
            None,
        )
        .expect("proof builds");
        let mut bytes = proof.to_bytes();
        // Flip a byte in the data_hash region (33..65).
        bytes[40] ^= 0xFF;
        let decoded = ZkTlsProof::from_bytes(&bytes).expect("still parses");
        // Signature no longer matches the altered hash → recovery yields a
        // different address than the signer's.
        let recovered = decoded.recover_signer().expect("recovers");
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..]);
        assert_ne!(recovered, expected);
    }

    #[test]
    fn prompt278_no_header_material_in_serialized_proof() {
        let sk = KSigningKey::random(&mut OsRng);
        let chain = test_chain();
        // The "secret" is a bearer token string the proxy used as a request
        // header. It is structurally absent from the proof payload (fixed
        // crypto fields only) — the redaction guard + byte-level assertion
        // make that mechanical (Prompt 278).
        let secret = "Bearer super-secret-token-12345";
        let proof = generate_proof(
            "https://api.example/data",
            br#"{"completed":true}"#,
            ".completed",
            &chain,
            &sk,
            [2u8; 16],
            Some(&[secret]),
        )
        .expect("proof builds — header value is absent from the payload");
        let bytes = proof.to_bytes();
        assert!(
            !bytes
                .windows(secret.as_bytes().len())
                .any(|w| w == secret.as_bytes()),
            "request header material must never appear in the proof payload"
        );
    }
}
