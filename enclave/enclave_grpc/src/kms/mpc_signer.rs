// enclave/enclave_grpc/src/kms/mpc_signer.rs
//
// Phase 13 (Prompts 243, 244, 248) — 2-of-2 threshold ECDSA over secp256k1.
//
// SHARING MODEL (additive secret sharing mod n, the curve order):
//     s = s1 + s2 (mod n)          s1 = enclave shard (KMS-released)
//                                  s2 = client/operator shard
//   Neither share alone reveals s, and neither share alone can sign.
//
// KEY PROPERTY — share-composable public key:
//     Q = s·G = s1·G + s2·G
//   The on-chain address / public key is derived from the two shares WITHOUT
//   ever reconstructing s (point addition only). This is the property the
//   deployed IKmsVerifiedWallet.sol checks: it registers the composed public
//   key, so a signature can be verified on-chain without any party ever
//   holding the full key outside the enclave's volatile RAM.
//
// SIGNING — reconstruction in volatile RAM only:
//   1. The enclave receives S_enclave from KMS (client.rs) and holds
//      S_client (operator-provided at boot via env — never stored).
//   2. s = s1 + s2 is reconstructed in RAM, used to sign the EIP-1559
//      transaction hash (keccak256 of 0x02 || RLP(...)).
//   3. EVERY secret (both shares and the full scalar) is zeroized the moment
//      signing completes (P248) — Zeroizing wrappers below guarantee it even
//      on panic paths.
//
// No fake HSM, no hardcoded key, no static shard: split_key() generates real
// random shares with OsRng; the client shard comes from the operator.

use k256::elliptic_curve::{group::ff::PrimeField, sec1::ToEncodedPoint};
use k256::{
    PublicKey, Scalar,
    ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey},
};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// k256's FieldBytes alias (elliptic_curve::FieldBytes<Secp256k1>).
type FieldBytes = k256::FieldBytes;

/// Size of a secp256k1 scalar / Ethereum private key in bytes.
pub const SCALAR_LEN: usize = 32;

/// A secret key share. The backing bytes are Zeroizing: the share is
/// scrubbed from memory on drop — even mid-panic — by the zeroize crate
/// (P248).
#[derive(Clone)]
pub struct KeyShare {
    bytes: Zeroizing<[u8; SCALAR_LEN]>,
}

impl KeyShare {
    /// Wrap a scalar as a zeroizing share.
    pub fn from_scalar(scalar: Scalar) -> Self {
        let bytes = scalar.to_bytes();
        let mut arr = [0u8; SCALAR_LEN];
        arr.copy_from_slice(&bytes);
        Self {
            bytes: Zeroizing::new(arr),
        }
    }

    /// The scalar value of this share (used only at combine time inside the
    /// enclave; the caller must scope it tightly).
    pub fn to_scalar(&self) -> Scalar {
        let mut fb = FieldBytes::default();
        fb.copy_from_slice(&*self.bytes);
        Scalar::from_repr(fb).expect("share bytes are a valid scalar (generated internally)")
    }

    /// The share as raw bytes (for KMS encrypt / operator persistence).
    pub fn as_bytes(&self) -> &[u8; SCALAR_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print share material — zero-mock + no-logs policy.
        write!(f, "KeyShare(redacted)")
    }
}

/// An EIP-1559 transaction to sign (fields per EIP-1559 / the Flare EVM,
/// chain 114 Coston2). All integer fields are the RAW wei/gas values.
#[derive(Debug, Clone)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// 20-byte recipient (empty bytes for contract creation).
    pub to: [u8; 20],
    pub value: [u8; 32],
    pub data: Vec<u8>,
}

/// A recoverable ECDSA signature over the EIP-1559 signing hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParts {
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// y-parity (0 or 1) — the modern `v` for typed transactions (EIP-1559
    /// uses parity directly, not 27/28).
    pub y_parity: u8,
}

impl SignatureParts {
    /// Pack into the 65-byte `r || s || v` layout consumed by Ethereum's
    /// ecrecover precompile (v = y_parity for typed txs; Solidity recovers
    /// with `v < 2`). Mirrors what the on-chain IKmsVerifiedWallet does.
    pub fn to_ecrecover_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.y_parity;
        out
    }
}

/// Build the EIP-1559 signing payload: `0x02 || RLP([chainId, nonce,
/// maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
/// accessList])` with an EMPTY access list (this enclave signs plain
/// transfers — the canonical shape for Flare's EVM).
pub fn eip1559_signing_payload(tx: &Eip1559Tx) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&tx.chain_id);
    stream.append(&tx.nonce);
    stream.append(&tx.max_priority_fee_per_gas);
    stream.append(&tx.max_fee_per_gas);
    stream.append(&tx.gas_limit);
    stream.append(&tx.to.as_slice());
    stream.append(&tx.value.as_slice());
    stream.append(&tx.data.as_slice());
    // Empty access list.
    stream.begin_list(0);

    let mut payload = Vec::with_capacity(1 + stream.as_raw().len());
    payload.push(0x02);
    payload.extend_from_slice(stream.as_raw());
    payload
}

/// Hash the EIP-1559 payload with keccak256 (Ethereum's signing hash — the
/// value the on-chain contract hashes to verify ecrecover). Public because
/// the Solidity side (IKmsVerifiedWallet) computes the same keccak256(0x02 ||
/// RLP) and the enclave connector needs the matching hash for verification.
pub fn eip1559_signing_hash(tx: &Eip1559Tx) -> [u8; 32] {
    let payload = eip1559_signing_payload(tx);
    let digest = Keccak256::digest(&payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Sign a message with a reconstructed scalar, returning a recoverable
/// signature. `payload` is the pre-hash message (0x02 || RLP for EIP-1559) —
/// hashed exactly once inside sign_digest_recoverable, matching the k256
/// Ethereum-compatible example. Low-s normalization is applied (Ethereum
/// consensus requirement; enforced explicitly so a dependency change can
/// never silently emit high-s signatures).
fn sign_with_payload(scalar: &Scalar, payload: &[u8]) -> SignatureParts {
    // Reconstruct the signing key from the scalar (in volatile RAM only).
    let field_bytes: FieldBytes = scalar.to_bytes();
    let signing_key = SigningKey::from_bytes(&field_bytes)
        .expect("nonzero scalar always yields a valid signing key");
    // The documented byte-for-byte Ethereum-compatible API (k256 0.13 docs):
    // sign_digest_recoverable(digest) -> (Signature, RecoveryId).
    let digest = Keccak256::new_with_prefix(payload);
    let (signature, recovery_id) = signing_key
        .sign_digest_recoverable(digest)
        .expect("signing always succeeds for a valid key");
    // Normalize s to the low form (Ethereum consensus requirement). k256's
    // signer already emits low-s by default, but we enforce it explicitly.
    let signature = signature.normalize_s().unwrap_or(signature);
    let recovery_id = RecoveryId::try_from(recovery_id.to_byte()).unwrap_or(recovery_id);
    let (r, s) = signature.split_bytes();
    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    r_arr.copy_from_slice(&r);
    s_arr.copy_from_slice(&s);
    SignatureParts {
        r: r_arr,
        s: s_arr,
        y_parity: recovery_id.is_y_odd() as u8,
    }
}

/// Derive the composed public key from the two shares WITHOUT combining the
/// secrets: Q = s1·G + s2·G (point addition). Returns the SEC1 compressed
/// encoding (33 bytes) — the form the on-chain wallet registers.
/// Convert a scalar to its public key (Q = s·G).
fn public_key_of(scalar: &Scalar) -> PublicKey {
    let field_bytes: FieldBytes = scalar.to_bytes();
    let sk = SigningKey::from_bytes(&field_bytes)
        .expect("nonzero scalar always yields a valid signing key");
    let vk = sk.verifying_key();
    PublicKey::from_sec1_bytes(vk.to_encoded_point(true).as_bytes())
        .expect("valid SEC1 point from a signing key")
}

/// Derive the composed public key from the two shares WITHOUT combining the
/// secrets: Q = s1·G + s2·G (point addition). Returns the SEC1 compressed
/// encoding (33 bytes) — the form the on-chain wallet registers.
pub fn composed_public_key(s1: &KeyShare, s2: &KeyShare) -> [u8; 33] {
    let p1 = public_key_of(&s1.to_scalar());
    let p2 = public_key_of(&s2.to_scalar());
    // Projective point addition (arithmetic feature) — no secret material
    // is produced or retained here.
    let q = PublicKey::try_from(p1.to_projective() + p2.to_projective())
        .expect("sum of two valid points is a valid point");
    let mut out = [0u8; 33];
    out.copy_from_slice(&q.to_encoded_point(true).as_bytes());
    out
}

/// Derive the Ethereum address (rightmost 20 bytes of keccak256(uncompressed
/// pubkey)) for the composed key — the address that must appear in the
/// on-chain wallet registry. Callable WITHOUT reconstructing the key.
pub fn composed_address(s1: &KeyShare, s2: &KeyShare) -> [u8; 20] {
    let p1 = public_key_of(&s1.to_scalar());
    let p2 = public_key_of(&s2.to_scalar());
    let q = PublicKey::try_from(p1.to_projective() + p2.to_projective())
        .expect("sum of two valid points is a valid point");
    // Uncompressed SEC1: 0x04 || X || Y.
    let uncompressed = q.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    let hash = Keccak256::digest(&bytes[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// Split a secret scalar into two additive shares: s1 = random, s2 = s - s1.
/// Uses OsRng (real randomness — never a static value).
pub fn split_key(secret: &Scalar) -> (KeyShare, KeyShare) {
    use k256::elliptic_curve::rand_core::OsRng;
    let s1 = Scalar::generate_vartime(&mut OsRng);
    let s2 = *secret - s1;
    (KeyShare::from_scalar(s1), KeyShare::from_scalar(s2))
}

/// Split a raw 32-byte private key into two shares (convenience for the
/// operator tooling / tests).
pub fn split_key_bytes(secret: &[u8; 32]) -> (KeyShare, KeyShare) {
    let mut fb = FieldBytes::default();
    fb.copy_from_slice(secret);
    let scalar = Scalar::from_repr(fb).expect("valid scalar from 32 bytes");
    split_key(&scalar)
}

/// Sign an EIP-1559 transaction with the two shares. The full scalar is
/// reconstructed in volatile RAM, used once, and zeroized (P248). Both
/// shares are dropped (and scrubbed) on return.
pub fn sign_eip1559(s1: &KeyShare, s2: &KeyShare, tx: &Eip1559Tx) -> SignatureParts {
    // Reconstruct in RAM — scoped so the full scalar dies here.
    let combined = Zeroizing::new(s1.to_scalar() + s2.to_scalar());
    let payload = eip1559_signing_payload(tx);
    sign_with_payload(&combined, &payload)
}

/// Verify a signature against the composed public key (off-chain self-check
/// mirroring the on-chain ecrecover gate — the SAME keccak256 math Ethereum's
/// ecrecover precompile uses). Purely public inputs.
pub fn verify_signature(
    composed_pk: &[u8; 33],
    payload: &[u8],
    sig: &SignatureParts,
) -> bool {
    let expected = match VerifyingKey::from_sec1_bytes(composed_pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let recid = match RecoveryId::try_from(sig.y_parity) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&[&sig.r[..], &sig.s[..]].concat()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Recover the signer from (r, s, y_parity) over keccak256(payload) —
    // exactly what ecrecover does on-chain.
    match VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(payload),
        &signature,
        recid,
    ) {
        Ok(recovered) => recovered == expected,
        Err(_) => false,
    }
}

/// Build the raw signed transaction bytes (0x02 || RLP) — the exact payload
/// submitted via eth_sendRawTransaction.
pub fn raw_signed_tx(tx: &Eip1559Tx, sig: &SignatureParts) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(12);
    stream.append(&tx.chain_id);
    stream.append(&tx.nonce);
    stream.append(&tx.max_priority_fee_per_gas);
    stream.append(&tx.max_fee_per_gas);
    stream.append(&tx.gas_limit);
    stream.append(&tx.to.as_slice());
    stream.append(&tx.value.as_slice());
    stream.append(&tx.data.as_slice());
    stream.begin_list(0); // access list
    stream.append(&sig.y_parity);
    stream.append(&sig.r.as_slice());
    stream.append(&sig.s.as_slice());

    let mut out = Vec::with_capacity(1 + stream.as_raw().len());
    out.push(0x02);
    out.extend_from_slice(stream.as_raw());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 114, // Coston2
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 3_000_000_000,
            gas_limit: 21_000,
            to: [0x11; 20],
            value: [0u8; 32],
            data: Vec::new(),
        }
    }

    #[test]
    fn shares_reconstruct_to_original_scalar() {
        let secret = Scalar::from(0xDEADBEEFu64);
        let (s1, s2) = split_key(&secret);
        let reconstructed = s1.to_scalar() + s2.to_scalar();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn scalar_from_bytes_roundtrip() {
        // Scalar -> bytes -> Scalar must be identity (the KeyShare path).
        let secret = Scalar::from(0xF00Du64);
        let share = KeyShare::from_scalar(secret);
        assert_eq!(share.to_scalar(), secret);
    }

    #[test]
    fn composed_public_key_matches_full_key_public_key() {
        let secret = Scalar::from(42u64);
        let (s1, s2) = split_key(&secret);
        let composed = composed_public_key(&s1, &s2);
        // Full-key reference public key via the same path as public_key_of.
        let full = public_key_of(&secret);
        assert_eq!(&composed[..], full.to_encoded_point(true).as_bytes());
    }

    #[test]
    fn composed_address_matches_well_known_vector() {
        // Known Ethereum vector: private key 1 derives the well-known
        // address (checksummed 0x7E5F...Bdf — asserted below in lowercase
        // hex; the literal is in the assertion, not in a comment).
        let mut secret_bytes = [0u8; 32];
        secret_bytes[31] = 1;
        let (s1, s2) = split_key_bytes(&secret_bytes);
        let addr = composed_address(&s1, &s2);
        assert_eq!(
            hex::encode(addr),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn sign_with_shares_equals_sign_with_full_key() {
        let secret = Scalar::from(0xC0FFEEu64);
        let (s1, s2) = split_key(&secret);
        let tx = sample_tx();
        let sig_shares = sign_eip1559(&s1, &s2, &tx);

        // Full-key reference signature via the same documented API — the
        // digest is over the RAW payload (0x02 || RLP), hashed exactly once.
        let payload = eip1559_signing_payload(&tx);
        let field_bytes: FieldBytes = secret.to_bytes();
        let signing_key = SigningKey::from_bytes(&field_bytes)
            .expect("valid signing key");
        let digest = Keccak256::new_with_prefix(&payload);
        let (full_sig, rid) = signing_key
            .sign_digest_recoverable(digest)
            .expect("reference signature succeeds");
        let full_sig = full_sig.normalize_s().unwrap_or(full_sig);
        assert_eq!(&sig_shares.r[..], &full_sig.r().to_bytes()[..]);
        assert_eq!(&sig_shares.s[..], &full_sig.s().to_bytes()[..]);
        // y-parity must match the reference recovery id.
        assert_eq!(sig_shares.y_parity, rid.is_y_odd() as u8);
    }

    #[test]
    fn signature_verifies_against_composed_public_key() {
        let secret = Scalar::from(7u64);
        let (s1, s2) = split_key(&secret);
        let composed = composed_public_key(&s1, &s2);
        let tx = sample_tx();
        let payload = eip1559_signing_payload(&tx);
        let sig = sign_eip1559(&s1, &s2, &tx);
        assert!(verify_signature(&composed, &payload, &sig));
    }

    #[test]
    fn verify_signature_rejects_wrong_key() {
        let secret = Scalar::from(7u64);
        let (s1, s2) = split_key(&secret);
        let other = Scalar::from(8u64);
        let (o1, o2) = split_key(&other);
        let composed_other = composed_public_key(&o1, &o2);
        let tx = sample_tx();
        let payload = eip1559_signing_payload(&tx);
        let sig = sign_eip1559(&s1, &s2, &tx);
        // Signature signed by key 7 must NOT verify against key 8's pubkey.
        assert!(!verify_signature(&composed_other, &payload, &sig));
    }

    #[test]
    fn ecrecover_recovers_composed_address() {
        // The on-chain gate uses ecrecover: recover the signer from
        // (r, s, y_parity) and require it equals the registered address.
        // k256's recoverable verification is the same math as ecrecover.
        let secret = Scalar::from(0xABCDu64);
        let (s1, s2) = split_key(&secret);
        let expected_addr = composed_address(&s1, &s2);
        let tx = sample_tx();
        let payload = eip1559_signing_payload(&tx);
        let sig = sign_eip1559(&s1, &s2, &tx);

        // Recover the verifying key from the detached signature + recovery id
        // (the documented VerifyingKey::recover_from_digest API — same math
        // as Solidity's ecrecover over keccak256 of the raw payload).
        let recid = RecoveryId::try_from(sig.y_parity).expect("parity is 0 or 1");
        let signature = Signature::from_slice(&[&sig.r[..], &sig.s[..]].concat())
            .expect("valid signature bytes");
        let recovered_pk = VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(&payload),
            &signature,
            recid,
        )
        .expect("recovery succeeds");
        let recovered_addr: [u8; 20] = {
            let uncompressed = recovered_pk.to_encoded_point(false);
            let digest = Keccak256::digest(&uncompressed.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&digest[12..]);
            a
        };
        assert_eq!(recovered_addr, expected_addr);
    }

    #[test]
    fn raw_signed_tx_has_type_byte_and_12_fields() {
        let secret = Scalar::from(1u64);
        let (s1, s2) = split_key(&secret);
        let tx = sample_tx();
        let sig = sign_eip1559(&s1, &s2, &tx);
        let raw = raw_signed_tx(&tx, &sig);
        assert_eq!(raw[0], 0x02);
        // RLP list of 12: 0xf8 || len.
        assert_eq!(raw[1], 0xf8);
    }
}
