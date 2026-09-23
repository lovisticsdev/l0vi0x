// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

address constant VM = address(uint160(uint256(keccak256("hevm cheat code"))));
