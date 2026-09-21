// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EconHarness} from "../lib/EconHarness.sol";
import {Attacker} from "../lib/Attacker.sol";

interface HarnessCreate2Factory { function deploy(bytes32 salt, bytes calldata initCode) external returns (address); }

contract DeployedForkWitness is Test {
    uint256 internal constant FORK_BLOCK = {{ FORK_BLOCK }};
    uint256 internal constant INITIAL_CAPITAL_WEI = {{ INITIAL_CAPITAL_WEI }};
    address internal constant ATTACKER = {{ ATTACKER_ADDRESS }};
    address internal constant HARNESS_DEPLOYER = {{ HARNESS_DEPLOYER }};
    bytes32 internal constant HARNESS_SALT = {{ HARNESS_SALT }};
    EconHarness internal harness;
    Attacker internal attacker;

    function setUp() public {
        vm.createSelectFork("l0vi0x_gate", FORK_BLOCK);
        attacker = new Attacker();
        // HARNESS_DEPLOYER is a pinned CREATE2 factory supplied by the deployment plan.
        bytes memory initCode = abi.encodePacked(type(EconHarness).creationCode, abi.encode(HARNESS_DEPLOYER));
        harness = EconHarness(HarnessCreate2Factory(HARNESS_DEPLOYER).deploy(HARNESS_SALT, initCode));
        vm.deal(ATTACKER, INITIAL_CAPITAL_WEI);
    }

    function test_witness() public {
        {{ BEFORE_BODY }}
        // BEGIN ATTACK BODY
{{ ATTACK_BODY }}
        // END ATTACK BODY
        {{ AFTER_BODY }}
    }

    function test_control() public {
        {{ CONTROL_BODY }}
    }
}
