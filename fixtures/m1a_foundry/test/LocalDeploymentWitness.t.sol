// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Vm} from "./Vm.sol";
import {M1aTarget} from "../src/M1aTarget.sol";
import {Create2HarnessFactory} from "../src/Create2HarnessFactory.sol";
import {WitnessHarness} from "./WitnessHarness.sol";

contract LocalDeploymentWitness {
    Vm internal constant vm = Vm(0x7109709ecfa91a80626ff3989d68f67f5b1dd12d);
    address internal constant ATTACKER = address(0xA11CE);
    bytes32 internal constant HARNESS_SALT = keccak256("l0vi0x-m1a-local");
    M1aTarget internal target;
    Create2HarnessFactory internal factory;
    WitnessHarness internal harness;

    function setUp() public {
        target = new M1aTarget();
        factory = new Create2HarnessFactory();
        bytes memory initCode = abi.encodePacked(type(WitnessHarness).creationCode, abi.encode(address(factory)));
        harness = WitnessHarness(factory.deploy(HARNESS_SALT, initCode));
        emit WitnessHarness.HarnessDeployed(address(harness), address(factory), HARNESS_SALT);
        vm.deal(ATTACKER, 1 ether);
    }

    function test_witness() public {
        uint256 beforeValue = target.snapshot(ATTACKER);
        target.fund{value: 0}(ATTACKER, 7);
        uint256 afterValue = target.snapshot(ATTACKER);
        harness.check(keccak256("A-local"), "credit", int256(afterValue-beforeValue), 7);
        vm.warp(1001);
        vm.roll(2);
    }

    function test_control() public {
        uint256 beforeValue = target.snapshot(ATTACKER);
        require(beforeValue == 0, "setup changed target");
    }
}
