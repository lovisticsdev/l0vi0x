// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {IOracle} from "./LendingPool.sol";

contract MutableOracle is IOracle {
    uint256 public price;

    constructor(uint256 initialPrice) {
        price = initialPrice;
    }

    function setPrice(uint256 nextPrice) external {
        price = nextPrice;
    }
}
