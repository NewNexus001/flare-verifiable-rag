// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZkTlsRelayer
 * @notice Minimal interface to the zkTLS relayer (ZkTlsRelayer.sol) as
 *         consumed by VerifiableRAG.sol (Phase 14, Prompt 272).
 *
 * The relayer verifies enclave-signed zkTLS proofs (ecrecover over the
 * canonical payload) and records verifiedWeb2Data[urlHash] = dataHash — the
 * sub-second Web2 attestation path that bypasses the ~90s FDC voting round.
 */
interface IZkTlsRelayer {
    /// The verified record for a URL.
    struct VerifiedData {
        bytes32 dataHash;
        uint256 verifiedAt;
    }

    /// @notice The verified Web2 data hash recorded for `urlHash`
    ///         (bytes32(0) when never verified).
    function verifiedWeb2Data(
        bytes32 urlHash
    ) external view returns (VerifiedData memory);
}
