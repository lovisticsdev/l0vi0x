// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

contract WitnessHarness {
    address public immutable WRAPPER;
    event AssertionChecked(bytes32 indexed id, string kind, string target, int256 observed, int256 expected, bool ok);
    event HarnessDeployed(address indexed harness, address indexed deployer, bytes32 indexed salt);
    constructor(address wrapper) { WRAPPER = wrapper; }
    modifier onlyWrapper(){ require(msg.sender == WRAPPER, "wrapper"); _; }
    function check(bytes32 id, string calldata target, int256 observed, int256 expected) external onlyWrapper {
        bool ok = observed == expected;
        emit AssertionChecked(id, "custom", target, observed, expected, ok);
        require(ok, "assertion mismatch");
    }
}
