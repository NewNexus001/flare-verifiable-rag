// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Unit-test stand-in for FtsoV2 (Prompt 118 coverage): returns a caller-
///      controlled (value, decimals, timestamp) triple. Branch-light by design
///      (one unconditional return) so it never dilutes the coverage report.
///      Production settlement uses the REAL FtsoV2 resolved LIVE from the
///      registry (contracts/VerifiableRAG.sol ftsoV2()).
contract TestFtsoV2 {
    uint256 private _value;
    int8 private _decimals = 8;
    uint64 private _timestamp;

    function setFeed(uint256 value, uint64 timestamp) external {
        _value = value;
        _timestamp = timestamp;
    }

    function setDecimals(int8 decimals) external {
        _decimals = decimals;
    }

    function getFeedById(
        bytes21 /* _feedId */
    ) external view returns (uint256 value, int8 decimals, uint64 timestamp) {
        return (_value, _decimals, _timestamp);
    }
}
