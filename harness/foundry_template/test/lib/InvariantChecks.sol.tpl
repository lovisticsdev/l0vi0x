// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

abstract contract InvariantChecks {
    // Generated M1b assertion helpers are pinned by the witness.
    function l0vi0xInvariantCheck(bytes32 id, bool ok) internal pure returns (bytes32) {
        require(ok, "invariant failed");
        return id;
    }
}
