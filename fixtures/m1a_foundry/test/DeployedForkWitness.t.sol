// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Vm} from "./Vm.sol";
import {M1aTarget} from "../src/M1aTarget.sol";
import {Create2HarnessFactory} from "../src/Create2HarnessFactory.sol";
import {WitnessHarness} from "./WitnessHarness.sol";

contract DeployedForkWitness {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    address internal constant ATTACKER = address(0xA11CE);
    bytes32 internal constant HARNESS_SALT = keccak256("l0vi0x-m1a-fork");
    uint256 internal constant FORK_BLOCK = 3;
    M1aTarget internal target;
    Create2HarnessFactory internal factory;
    WitnessHarness internal harness;

    function setUp() public {
        vm.createSelectFork("l0vi0x_gate", FORK_BLOCK);
        target = M1aTarget(0x5FbDB2315678afecb367f032d93F642f64180aa3);
        // Fixture target state is already present in the pinned fork. The harness is deployment-only setup.
        factory = new Create2HarnessFactory();
        bytes memory initCode = abi.encodePacked(
            type(WitnessHarness).creationCode,
            abi.encode(address(factory), address(target))
        );
        harness = WitnessHarness(factory.deploy(HARNESS_SALT, initCode));
        emit WitnessHarness.HarnessDeployed(address(harness), address(factory), HARNESS_SALT);
    }

    function test_witness() public {
        // BEGIN ATTACK BODY
        uint256 observed = target.snapshot(ATTACKER);
        require(observed == 3, "pinned fork state mismatch");
        // BEGIN WRAPPER CALLSITE
        factory.check(
            address(harness),
            keccak256("A-fork"),
            ATTACKER,
            "credit",
            3
        );
        // END WRAPPER CALLSITE
        vm.warp(1700000101);
        vm.roll(4);
        // END ATTACK BODY
    }

    function test_control() public {
        uint256 value = target.snapshot(ATTACKER);
        require(value >= 0, "control");
    }
}
