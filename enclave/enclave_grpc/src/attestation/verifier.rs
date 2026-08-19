// enclave/enclave_grpc/src/attestation/verifier.rs
//
// Phase 12 (Prompts 226, 227) — offline EAT claim validation.
//
// Verifies a COSE_Sign1 EAT token WITHOUT network access:
//   1. parse the envelope (RFC 9052 §4.2)
//   2. check the protected header declares alg = ES256 (-7)
//   3. recompute the Sig_structure and verify the ES256 signature with the
//      expected verifying key
//   4. decode the EAT claim set and enforce the policy checks:
//        swname      == expected (e.g. "CONFIDENTIAL_SPACE")
//        image_digest == expected build digest (sha256:…)
//        nonce        == expected session nonce (replay/session binding)
//
// On the Linux TDX path the verifying key is derived from the Intel
// attestation root chain (Intel TDX quote verification); on this dev host
// the emulator test keys exercise the same code path.
#![allow(dead_code)]

use crate::attestation::eat_builder::{
    decode_claims, parse_cose_sign1, sig_structure, CLAIM_IAT, CLAIM_NONCE, CLAIM_SUBMODS,
    CLAIM_SWNAME, COSE_HEADER_ALG, ALG_ES256,
};
use ciborium::value::Value;
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum EatVerifyError {
    Malformed(&'static str),
    UnsupportedAlg(i128),
    /// ECDSA verification failed (bad signature / tampered payload).
    BadSignature(p256::ecdsa::Error),
    /// Policy check failed — claim did not match expectations.
    Policy(&'static str),
    MissingClaim(&'static str),
}

impl std::fmt::Display for EatVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EatVerifyError::Malformed(m) => write!(f, "malformed EAT: {m}"),
            EatVerifyError::UnsupportedAlg(a) => write!(f, "unsupported COSE alg {a} (expected ES256)"),
            EatVerifyError::BadSignature(e) => write!(f, "EAT signature verification failed: {e}"),
            EatVerifyError::Policy(m) => write!(f, "EAT policy check failed: {m}"),
            EatVerifyError::MissingClaim(m) => write!(f, "EAT missing claim: {m}"),
        }
    }
}

impl std::error::Error for EatVerifyError {}

/// Verified claims extracted from an accepted token.
#[derive(Debug, Clone)]
pub struct VerifiedEat {
    pub nonce: Vec<u8>,
    pub swname: String,
    pub image_digest: String,
    pub hardware: String,
    pub iat: u64,
}

/// Step 1+2+3: verify the COSE signature and return the raw payload bytes.
pub fn verify_cose_sign1(token: &[u8], verifying_key: &VerifyingKey) -> Result<Vec<u8>, EatVerifyError> {
    let parsed = parse_cose_sign1(token).map_err(|_| EatVerifyError::Malformed("parse failed"))?;

    // Protected header must declare alg = ES256.
    let alg = match &parsed.protected_map {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Value::Integer(i)
                if *i == ciborium::value::Integer::from(COSE_HEADER_ALG as i64) =>
            {
                Some(v)
            }
            _ => None,
        }),
        _ => None,
    }
    .ok_or(EatVerifyError::Malformed("protected header missing alg"))?;
    let alg_val: i128 = match alg {
        Value::Integer(i) => (*i).into(), // From<Integer> for i128
        _ => return Err(EatVerifyError::Malformed("alg must be an integer")),
    };
    if alg_val != ALG_ES256 {
        return Err(EatVerifyError::UnsupportedAlg(alg_val));
    }

    // Recompute Sig_structure over the exact protected + payload bytes.
    let sig_input = sig_structure(&parsed.protected, &parsed.payload);
    let mut sig_input_bytes = Vec::new();
    ciborium::ser::into_writer(&sig_input, &mut sig_input_bytes)
        .map_err(|_| EatVerifyError::Malformed("sig structure encode failed"))?;

    // ES256 signatures are 64-byte r||s (RFC 9053) — convert to a Signature.
    let sig_bytes: [u8; 64] = parsed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| EatVerifyError::Malformed("signature must be 64 bytes (r||s)"))?;
    let signature = p256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|_e| EatVerifyError::Malformed("invalid signature encoding"))?;

    verifying_key
        .verify(&sig_input_bytes, &signature)
        .map_err(EatVerifyError::BadSignature)?;

    Ok(parsed.payload)
}

/// Extract a claim from the EAT claim map by integer key.
fn claim<'a>(claims: &'a Value, key: i128) -> Option<&'a Value> {
    match claims {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| {
                matches!(
                    k,
                    Value::Integer(i) if *i == ciborium::value::Integer::from(key as i64)
                )
            })
            .map(|(_, v)| v),
        _ => None,
    }
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

/// Extract the image digest from submods.container.image_digest.
fn container_digest(claims: &Value) -> Option<String> {
    let submods = claim(claims, CLAIM_SUBMODS)?;
    let container = match submods {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Value::Text(s) if s == "container" => Some(v),
            _ => None,
        })?,
        _ => return None,
    };
    match container {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Value::Text(s) if s == "image_digest" => as_text(v),
            _ => None,
        }),
        _ => None,
    }
}

fn container_hardware(claims: &Value) -> Option<String> {
    let submods = claim(claims, CLAIM_SUBMODS)?;
    let container = match submods {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Value::Text(s) if s == "container" => Some(v),
            _ => None,
        })?,
        _ => return None,
    };
    match container {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Value::Text(s) if s == "hardware" => as_text(v),
            _ => None,
        }),
        _ => None,
    }
}

/// Step 4: validate the decoded claims against expected build parameters.
///
/// `expected_digest` — if Some, the token's image_digest must equal it
/// (Prompt 227: digest must match the recorded build digest).
pub fn validate_claims(
    payload: &[u8],
    expected_swname: &str,
    expected_digest: Option<&str>,
    expected_nonce: Option<&[u8]>,
) -> Result<VerifiedEat, EatVerifyError> {
    let claims = decode_claims(payload).map_err(|_| EatVerifyError::Malformed("claims decode failed"))?;

    let swname = claim(&claims, CLAIM_SWNAME)
        .and_then(as_text)
        .ok_or(EatVerifyError::MissingClaim("swname"))?;
    if swname != expected_swname {
        return Err(EatVerifyError::Policy("swname does not match expected value"));
    }

    let image_digest = container_digest(&claims)
        .ok_or(EatVerifyError::MissingClaim("submods.container.image_digest"))?;
    if let Some(expected) = expected_digest {
        if image_digest != expected {
            return Err(EatVerifyError::Policy("image_digest does not match expected build digest"));
        }
    }

    let nonce = claim(&claims, CLAIM_NONCE)
        .and_then(as_bytes)
        .ok_or(EatVerifyError::MissingClaim("nonce"))?;
    if let Some(expected) = expected_nonce {
        if nonce != expected {
            return Err(EatVerifyError::Policy("nonce does not match session nonce"));
        }
    }

    let iat = claim(&claims, CLAIM_IAT)
        .and_then(|v| match v {
            Value::Integer(i) => {
                let n: i128 = (*i).into();
                (n >= 0).then_some(n as u64)
            }
            _ => None,
        })
        .ok_or(EatVerifyError::MissingClaim("iat"))?;

    Ok(VerifiedEat {
        nonce,
        swname,
        image_digest,
        hardware: container_hardware(&claims).unwrap_or_default(),
        iat,
    })
}

/// Convenience: full offline verification (signature + policy) in one call.
pub fn verify_eat(
    token: &[u8],
    verifying_key: &VerifyingKey,
    expected_swname: &str,
    expected_digest: Option<&str>,
    expected_nonce: Option<&[u8]>,
) -> Result<VerifiedEat, EatVerifyError> {
    let payload = verify_cose_sign1(token, verifying_key)?;
    validate_claims(&payload, expected_swname, expected_digest, expected_nonce)
}

/// Hash helper used to bind caller nonces (kept here for the verifier side).
#[allow(dead_code)]
pub fn hash_bytes(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
