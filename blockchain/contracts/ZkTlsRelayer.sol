// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ZkTlsRelayer
 * @notice On-chain verifier for the enclave's zkTLS proofs (Phase 14,
 *         Prompts 267-268).
 *
 * The enclave (zktls/proxy.rs + proof_generator.rs) opens a TLS 1.3 session
 * to a Web2 API from inside the TEE, validates the server's certificate
 * chain against the Mozilla root bundle, runs a jq selector over the
 * decrypted payload, and signs a canonical payload binding:
 *   url_hash, data_hash (jq output), response_hash (full body),
 *   cert_fingerprint (chain), timestamp, nonce
 * with its secp256k1 identity key (the SAME k256 recoverable-signature math
 * as the Phase 13 MPC wallet).
 *
 * `relayVerifiedWeb2Data` recomputes that payload from the proof bytes +
 * the (urlHash, dataHash) arguments, recovers the signer with ecrecover,
 * and requires it to be a registered enclave identity. On success it
 * records verifiedWeb2Data[urlHash] = dataHash — the sub-second attestation
 * path that bypasses the ~90s FDC voting round (master plan: "the enclave
 * signs the zkTLS proof using its hardware-bound ECDSA identity key and
 * posts it directly to VerifiableRAG.sol").
 *
 * Proof wire format (byte layout — MUST match
 * enclave/enclave_grpc/src/zktls/proof_generator.rs ZkTlsProof::to_bytes):
 *   version(1) || url_hash(32) || data_hash(32) || response_hash(32) ||
 *   cert_fingerprint(32) || timestamp(8 BE) || nonce(16) ||
 *   r(32) || s(32) || v(1 = recovery id 0/1)
 * Signed digest = keccak256(abi.encodePacked(version, urlHash, dataHash,
 *   responseHash, certFingerprint, timestamp, nonce)).
 */
contract ZkTlsRelayer is Ownable {
    /// Protocol version byte the relayer accepts (domain separation).
    uint8 public constant PROOF_VERSION = 1;

    /// Maximum accepted age of a proof's timestamp (seconds) — mirrors the
    /// FTSO v2 300s freshness window used across the platform (Prompt 145).
    uint64 public constant PROOF_MAX_AGE = 300;

    /// Registered enclave identity addresses (the keys that sign proofs).
    mapping(address signer => bool registered) public zkTlsSigners;

    /// Verified Web2 data: url_hash => (data_hash, verified_at).
    mapping(bytes32 urlHash => VerifiedData data) public verifiedWeb2Data;

    /// Replay prevention: digest hashes already consumed.
    mapping(bytes32 digest => bool used) public usedProofs;

    /// The verified record for a URL.
    struct VerifiedData {
        bytes32 dataHash;
        uint256 verifiedAt;
    }

    /// Reverts when the owner registers the zero address.
    error ZeroAddress();

    /// Reverts when a signer is already registered (no-op).
    error ZkTlsSignerAlreadyRegistered(address signer);

    /// Reverts when a signer is not registered (no-op).
    error ZkTlsSignerNotRegistered(address signer);

    /// Reverts when the proof has an unsupported version byte.
    error UnsupportedProofVersion(uint8 version);

    /// Reverts when the proof bytes are malformed (wrong length).
    error MalformedProof();

    /// Reverts when the proof's urlHash/dataHash do not match the arguments
    /// (the arguments are bound into the signed digest — a mismatch means
    /// the proof was relayed with different claims than it was signed for).
    error ProofHashMismatch();

    /// Reverts when the recovered signer is not a registered enclave identity.
    error UnauthorizedZkTlsSigner(address recovered);

    /// Reverts when ecrecover fails (unrecoverable signature).
    error ZeroZkTlsSigner();

    /// Reverts when the proof timestamp is outside the freshness window.
    error StaleProof();

    /// Reverts when the same proof digest was already relayed (replay).
    error ProofAlreadyUsed(bytes32 digest);

    /// Emitted when the owner registers an enclave identity address.
    event ZkTlsSignerRegistered(address indexed signer);

    /// Emitted when the owner deregisters an enclave identity address.
    event ZkTlsSignerDeregistered(address indexed signer);

    /// Emitted when a proof is verified and the Web2 data is recorded.
    event Web2DataRelayed(
        bytes32 indexed urlHash,
        bytes32 indexed dataHash,
        address indexed signer,
        bytes32 responseHash,
        bytes32 certFingerprint,
        uint256 timestamp
    );

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Register an enclave identity address (owner only).
    /// @dev Reverts `ZeroAddress` on address(0) and
    ///      `ZkTlsSignerAlreadyRegistered` on a no-op.
    function registerZkTlsSigner(address _signer) external onlyOwner {
        if (_signer == address(0)) {
            revert ZeroAddress();
        }
        if (zkTlsSigners[_signer]) {
            revert ZkTlsSignerAlreadyRegistered(_signer);
        }
        zkTlsSigners[_signer] = true;
        emit ZkTlsSignerRegistered(_signer);
    }

    /// @notice Deregister an enclave identity address (owner only).
    /// @dev Reverts `ZkTlsSignerNotRegistered` on a no-op.
    function deregisterZkTlsSigner(address _signer) external onlyOwner {
        if (!zkTlsSigners[_signer]) {
            revert ZkTlsSignerNotRegistered(_signer);
        }
        zkTlsSigners[_signer] = false;
        emit ZkTlsSignerDeregistered(_signer);
    }

    /// @notice True when `_signer` is a registered enclave identity.
    function isZkTlsSigner(address _signer) external view returns (bool) {
        return zkTlsSigners[_signer];
    }

    /**
     * @notice Verify an enclave-signed zkTLS proof and record the verified
     *         Web2 data (Prompt 268).
     *
     * On-chain checks (all real cryptography — ecrecover over the exact
     * digest the enclave signed):
     *   1. version byte matches {PROOF_VERSION};
     *   2. the proof's embedded url_hash/data_hash equal the `_urlHash` /
     *      `_dataHash` arguments (they are part of the signed digest, so a
     *      mismatch could only be produced by relaying a proof for DIFFERENT
     *      claims than it was signed for);
     *   3. timestamp within {PROOF_MAX_AGE} of block.timestamp (freshness);
     *   4. the digest was not already used (replay prevention);
     *   5. ecrecover(digest, v+27, r, s) yields a REGISTERED enclave
     *      identity.
     *
     * @param _proof   Serialized proof (see file header for the layout).
     * @param _urlHash keccak256/sha256 of the attested URL (as the enclave
     *                 bound it: sha256(url) — 32 bytes either way).
     * @param _dataHash Hash of the jq-selected output the enclave bound.
     * @return true when all checks pass and the data was recorded.
     * @dev Reverts `MalformedProof` on wrong length, `UnsupportedProofVersion`,
     *      `ProofHashMismatch`, `StaleProof`, `ProofAlreadyUsed`,
     *      `ZeroZkTlsSigner`, `UnauthorizedZkTlsSigner`.
     */
    /// Decoded proof fields (kept in one memory struct so the relay function
    /// stays within the EVM stack limit — 9 decoded fields + digest + signer
    /// would otherwise overflow the stack).
    struct ProofFields {
        uint8 version;
        bytes32 urlHash;
        bytes32 dataHash;
        bytes32 responseHash;
        bytes32 certFingerprint;
        uint64 ts;
        bytes16 nonce;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    /// Decode the fixed-layout proof bytes (see the file header for the
    /// layout — byte-for-byte the Rust ZkTlsProof::to_bytes wire format).
    /// @dev Reverts `MalformedProof` on a wrong length and
    ///      `UnsupportedProofVersion` on a bad version byte.
    function _decodeProof(bytes calldata _proof) private pure returns (ProofFields memory f) {
        if (_proof.length != 1 + 32 * 4 + 8 + 16 + 32 + 32 + 1) {
            revert MalformedProof();
        }
        f = ProofFields({
            version: uint8(_proof[0]),
            urlHash: bytes32(0),
            dataHash: bytes32(0),
            responseHash: bytes32(0),
            certFingerprint: bytes32(0),
            ts: 0,
            nonce: bytes16(0),
            r: bytes32(0),
            s: bytes32(0),
            v: 0
        });
        if (f.version != PROOF_VERSION) {
            revert UnsupportedProofVersion(f.version);
        }
        assembly ("memory-safe") {
            // url_hash at [1..33), data_hash [33..65), response [65..97),
            // fingerprint [97..129), timestamp [129..137), nonce [137..153),
            // r [153..185), s [185..217), v at [217].
            // (`ts` not `timestamp` — the latter is a reserved Yul builtin.)
            let src := _proof.offset
            mstore(add(f, 0x20), calldataload(add(src, 0x01))) // urlHash
            mstore(add(f, 0x40), calldataload(add(src, 0x21))) // dataHash
            mstore(add(f, 0x60), calldataload(add(src, 0x41))) // responseHash
            mstore(add(f, 0x80), calldataload(add(src, 0x61))) // certFingerprint
            mstore(add(f, 0xA0), shr(192, calldataload(add(src, 0x81)))) // ts (8B, low-aligned)
            // nonce is bytes16: the calldataload window [137..169) already
            // has it in the HIGH 16 bytes — mstore directly (a shr would
            // move it to the low half, which bytes16 does NOT read).
            mstore(add(f, 0xC0), calldataload(add(src, 0x89)))
            mstore(add(f, 0xE0), calldataload(add(src, 0x99))) // r
            mstore(add(f, 0x100), calldataload(add(src, 0xB9))) // s
            mstore(add(f, 0x120), byte(0, calldataload(add(src, 0xD9)))) // v
        }
    }

    function relayVerifiedWeb2Data(
        bytes calldata _proof,
        bytes32 _urlHash,
        bytes32 _dataHash
    ) external returns (bool) {
        // ---- 1) Decode the fixed-layout proof. ----
        ProofFields memory f = _decodeProof(_proof);

        // ---- 2) The arguments must match what the enclave signed. ----
        if (f.urlHash != _urlHash || f.dataHash != _dataHash) {
            revert ProofHashMismatch();
        }

        // ---- 3) Freshness window (mirrors the FTSO 300s rule). ----
        if (
            f.ts > block.timestamp + PROOF_MAX_AGE ||
            block.timestamp > f.ts + PROOF_MAX_AGE
        ) {
            revert StaleProof();
        }

        // ---- 4) Recompute the signed digest + replay check. ----
        bytes32 digest = keccak256(
            abi.encodePacked(
                f.version,
                f.urlHash,
                f.dataHash,
                f.responseHash,
                f.certFingerprint,
                f.ts,
                f.nonce
            )
        );
        if (usedProofs[digest]) {
            revert ProofAlreadyUsed(digest);
        }
        usedProofs[digest] = true;

        // ---- 5) Recover + authorize the signer. ----
        // The enclave stores the RAW recovery id (0/1); the EVM precompile
        // expects 27/28.
        address signer = ecrecover(digest, uint8(27 + f.v), f.r, f.s);
        if (signer == address(0)) {
            revert ZeroZkTlsSigner();
        }
        if (!zkTlsSigners[signer]) {
            revert UnauthorizedZkTlsSigner(signer);
        }

        // ---- 6) Record the verified Web2 data. ----
        verifiedWeb2Data[_urlHash] = VerifiedData({
            dataHash: _dataHash,
            verifiedAt: block.timestamp
        });
        emit Web2DataRelayed(
            _urlHash,
            _dataHash,
            signer,
            f.responseHash,
            f.certFingerprint,
            block.timestamp
        );
        return true;
    }
}
