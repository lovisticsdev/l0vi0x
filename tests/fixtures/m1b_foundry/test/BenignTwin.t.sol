// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Create2HarnessFactory} from "./Create2HarnessFactory.sol";
import {EconHarness} from "./lib/EconHarness.sol";
import {MockToken} from "../src/MockToken.sol";
import {MutableOracle} from "../src/MutableOracle.sol";
import {LendingPool} from "../src/LendingPool.sol";

contract BenignTwin {
    bytes32 internal constant SALT = bytes32(uint256(0x2222));
    MockToken internal token;
    MutableOracle internal oracle;
    LendingPool internal pool;
    Create2HarnessFactory internal factory;
    EconHarness internal harness;

    function setUp() public {
        token = new MockToken();
        oracle = new MutableOracle(0);
        pool = new LendingPool(token, oracle);
        token.mint(address(pool), 1_000 ether);
        factory = new Create2HarnessFactory();
        harness = EconHarness(factory.createHarness(SALT));
    }

    function test_witness() public {
        // BEGIN WRAPPER CALLSITE
        // BEGIN ATTACK BODY
        require(pool.maxBorrow() == 0, "benign twin is not fixed");
        // END ATTACK BODY
        // END WRAPPER CALLSITE
    }

    function test_control() public {
        require(pool.maxBorrow() == 0, "control");
    }
}
