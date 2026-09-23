// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface IWitnessHarness {
    function check(
        bytes32 id,
        address actor,
        string calldata targetName,
        int256 expected
    ) external;
}

contract WitnessWrapper {
    address public immutable HARNESS;

    constructor(address harness) {
        HARNESS = harness;
    }

    function check(
        bytes32 id,
        address actor,
        string calldata targetName,
        int256 expected
    ) external {
        IWitnessHarness(HARNESS).check(
            id,
            actor,
            targetName,
            expected
        );
    }
}
