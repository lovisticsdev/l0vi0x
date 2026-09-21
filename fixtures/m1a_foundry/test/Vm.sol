// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function warp(uint256 newTimestamp) external;
    function roll(uint256 newHeight) external;
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256);
    function envString(string calldata key) external returns (string memory);
    function startPrank(address sender) external;
    function stopPrank() external;
}
