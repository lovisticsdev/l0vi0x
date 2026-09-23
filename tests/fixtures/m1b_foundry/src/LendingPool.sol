// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface IMockToken {
    function balanceOf(address account) external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
}

interface IOracle {
    function price() external view returns (uint256);
}

/// @dev Deliberately vulnerable fixture: borrow capacity trusts a caller-controlled oracle price.
contract LendingPool {
    IMockToken public immutable token;
    IOracle public immutable oracle;
    uint256 public constant COLLATERAL = 1 ether;

    constructor(IMockToken token_, IOracle oracle_) {
        token = token_;
        oracle = oracle_;
    }

    function seed(uint256 amount) external {
        token.mint(address(this), amount);
    }

    function maxBorrow() public view returns (uint256) {
        return oracle.price();
    }

    function borrow(uint256 amount) external {
        require(amount <= maxBorrow(), "capacity");
        token.burn(address(this), amount);
        token.mint(msg.sender, amount);
    }
}
