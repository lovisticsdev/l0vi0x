// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

contract M1aTarget {
    mapping(address => uint256) public credit;
    event CreditChanged(address indexed actor, uint256 beforeValue, uint256 afterValue);

    function fund(address actor, uint256 amount) external payable {
        credit[actor] += amount;
        emit CreditChanged(actor, credit[actor] - amount, credit[actor]);
    }

    function snapshot(address actor) external view returns (uint256) {
        return credit[actor];
    }
}
