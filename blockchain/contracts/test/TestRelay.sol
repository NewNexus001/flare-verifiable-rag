// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Unit-test stand-in for the FDC Relay (Prompt 130/131): exposes a
///      caller-controlled `merkleRoots(protocolId, votingRound)` map — the
///      ONLY Relay member VerifiableRAG reads (via `_verifiedWeb2Root`).
///      Branch-light by design (one storage read) so it never dilutes the
///      coverage report. Production roots come from the REAL Relay resolved
///      through the live FdcVerification (`IFdcVerification.relay()`) —
///      exercised by the fork suite against real finalized rounds.
contract TestRelay {
    mapping(uint256 protocolId => mapping(uint256 votingRound => bytes32 root))
        private _roots;

    function setMerkleRoot(
        uint256 protocolId,
        uint256 votingRound,
        bytes32 root
    ) external {
        _roots[protocolId][votingRound] = root;
    }

    function merkleRoots(
        uint256 protocolId,
        uint256 votingRound
    ) external view returns (bytes32) {
        return _roots[protocolId][votingRound];
    }
}
