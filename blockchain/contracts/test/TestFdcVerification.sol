// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWeb2JsonVerification} from "../interfaces/IWeb2JsonVerification.sol";
import {IWeb2Json} from "../interfaces/IWeb2Json.sol";

/// @dev Unit-test stand-in for FdcVerification (Prompt 123): returns a
///      caller-controlled bool from verifyWeb2Json. Branch-light by design
///      (one unconditional return) so it never dilutes the coverage report.
///      Production verification uses the REAL FdcVerification resolved LIVE
///      from the registry (contracts/VerifiableRAG.sol verifyWeb2Data).
///      Prompt 130/131: also exposes a caller-controlled `relay()` (the TestRelay
///      holding the merkle root) and `fdcProtocolId()` (the REAL FDC protocol
///      id, 200 on Coston2) so VerifiableRAG._verifiedWeb2Root can resolve the
///      root the same way the live verifier does.
contract TestFdcVerification is IWeb2JsonVerification {
    bool private _result;
    address private _relay;
    uint8 private _protocolId = 200; // real FDC protocol id on Coston2

    function setResult(bool result) external {
        _result = result;
    }

    function setRelay(address relay_) external {
        _relay = relay_;
    }

    function setProtocolId(uint8 protocolId) external {
        _protocolId = protocolId;
    }

    function relay() external view returns (address) {
        return _relay;
    }

    function fdcProtocolId() external view returns (uint8) {
        return _protocolId;
    }

    function verifyWeb2Json(
        IWeb2Json.Proof calldata /* _proof */
    ) external view returns (bool _proved) {
        return _result;
    }
}
