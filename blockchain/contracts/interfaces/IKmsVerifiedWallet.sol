// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IKmsVerifiedWallet
 * @notice On-chain interface for verifying signatures produced by the
 *         enclave's GCP Cloud KMS MPC wallet (Phase 13, Prompts 249-250).
 *
 * The enclave holds a 2-of-2 MPC key (enclave shard from Cloud KMS +
 * operator shard, combined only in volatile RAM — see
 * enclave/enclave_grpc/src/kms/mpc_signer.rs). The composed public key's
 * Ethereum address is registered here by the owner. A transaction is
 * "KMS-verified" when ecrecover over its signing hash yields that address.
 *
 * ecrecover(keccak256(txType || RLP), v, r, s) is the SAME math the enclave
 * produces (k256 recoverable signatures, low-s normalized) — this is a real
 * cryptographic verification, not a marker or a flag.
 */
interface IKmsVerifiedWallet {
    /// Reverts when the signature's recovered signer is not a registered
    /// enclave MPC wallet address.
    error UnauthorizedSigner(address recovered);

    /// Reverts when the signer address is the zero address (unrecoverable).
    error ZeroSigner();

    /// Emitted when the owner registers an enclave MPC wallet address.
    event KmsSignerRegistered(address indexed signer);

    /// Emitted when the owner deregisters an enclave MPC wallet address.
    event KmsSignerDeregistered(address indexed signer);

    /// @notice True when `signer` is a registered enclave MPC wallet address.
    function isKmsSigner(address signer) external view returns (bool);

    /// @notice Recover the signer of `hash` from `(v, r, s)` and require it
    ///         to be a registered enclave MPC wallet address.
    /// @return The recovered, registered signer address.
    /// @dev Reverts `ZeroSigner` when ecrecover fails and
    ///      `UnauthorizedSigner` when the recovered address is unregistered.
    function requireKmsSignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view returns (address);
}
