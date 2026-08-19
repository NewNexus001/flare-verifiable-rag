// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Unit-test stand-in for FlareContractRegistry (Prompt 118 coverage).
///      Kept intentionally branch-light: a plain name->address map. Lives under
///      contracts/test/ so solidity-coverage excludes it (skipFiles "test/**")
///      — it carries zero production logic and must not dilute the report.
///      The production contract resolves the REAL registry (immutable bootstrap
///      from deploy.ts) — this helper only lets the deterministic suite exercise
///      the resolver branches (fdcHub/fdcVerification/ftsoV2 + Unregistered).
contract TestFlareRegistry {
    mapping(string => address) private _addresses;

    function setAddress(string calldata _name, address _addr) external {
        _addresses[_name] = _addr;
    }

    function getContractAddressByName(
        string calldata _name
    ) external view returns (address) {
        return _addresses[_name];
    }
}
