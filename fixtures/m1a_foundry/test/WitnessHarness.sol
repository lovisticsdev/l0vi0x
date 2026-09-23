// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface IM1aTarget {
    function snapshot(address actor) external view returns (uint256);
}

contract WitnessHarness {
    address public immutable WRAPPER;
    address public immutable TARGET;

    event AssertionChecked(
        bytes32 indexed id,
        string kind,
        string target,
        int256 observed,
        int256 expected,
        bool ok
    );

    event HarnessDeployed(
        address indexed harness,
        address indexed deployer,
        bytes32 indexed salt
    );

    constructor(address wrapper, address target) {
        WRAPPER = wrapper;
        TARGET = target;
    }

    modifier onlyWrapper() {
        require(msg.sender == WRAPPER, "wrapper");
        _;
    }

    function check(
        bytes32 id,
        address actor,
        string calldata targetName,
        int256 expected
    ) external onlyWrapper {
        uint256 observedRaw = IM1aTarget(TARGET).snapshot(actor);
        int256 observed = int256(observedRaw);

        bool ok = observed == expected;

        emit AssertionChecked(
            id,
            "custom",
            targetName,
            observed,
            expected,
            ok
        );

        require(ok, "assertion mismatch");
    }
}