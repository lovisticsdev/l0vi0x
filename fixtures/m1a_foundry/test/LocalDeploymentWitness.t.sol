// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Vm} from "./Vm.sol";
import {M1aTarget} from "../src/M1aTarget.sol";
import {Create2HarnessFactory} from "../src/Create2HarnessFactory.sol";
import {WitnessHarness} from "./WitnessHarness.sol";

contract LocalDeploymentWitness {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    address internal constant ATTACKER = address(0xA11CE);
    bytes32 internal constant HARNESS_SALT = keccak256("l0vi0x-m1a-local");
    M1aTarget internal target;
    Create2HarnessFactory internal factory;
    WitnessHarness internal harness;

    function setUp() public {
        target = new M1aTarget();
        factory = new Create2HarnessFactory();
        bytes memory initCode = abi.encodePacked(
            type(WitnessHarness).creationCode,
            abi.encode(address(factory), address(target))
        );
        harness = WitnessHarness(factory.deploy(HARNESS_SALT, initCode));
        emit WitnessHarness.HarnessDeployed(address(harness), address(factory), HARNESS_SALT);
        vm.deal(ATTACKER, 1 ether);
    }

    function test_witness() public {
        // BEGIN ATTACK BODY
        target.fund{value: 0}(ATTACKER, 7);
        // BEGIN WRAPPER CALLSITE
        factory.check(
            address(harness),
            keccak256("A-local"),
            ATTACKER,
            "credit",
            7
        );
        // END WRAPPER CALLSITE
        vm.warp(1001);
        vm.roll(2);
        // END ATTACK BODY
    }

    function test_control() public {
        uint256 beforeValue = target.snapshot(ATTACKER);
        require(beforeValue == 0, "setup changed target");
    }
}
