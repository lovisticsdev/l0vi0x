// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
}

contract EconHarness {
    address public immutable WRAPPER;

    event AssertionChecked(
        bytes32 indexed id,
        string kind,
        string target,
        int256 observed,
        int256 expected,
        bool ok
    );

    constructor(address wrapper_) {
        WRAPPER = wrapper_;
    }

    modifier onlyWrapper() {
        require(msg.sender == WRAPPER, "harness caller");
        _;
    }

    function snap(address actor, address[] memory tokens)
        external view onlyWrapper returns (uint256 eth, uint256[] memory tokenBalances)
    {
        eth = actor.balance;
        tokenBalances = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenBalances[i] = IERC20Like(tokens[i]).balanceOf(actor);
        }
    }

    function assertBalanceDelta(
        bytes32 id,
        address actor,
        address token,
        uint256 beforeBal,
        uint256 afterBal,
        int256 expectedDelta
    ) external onlyWrapper {
        int256 observed = int256(afterBal) - int256(beforeBal);
        bool ok = observed == expectedDelta;
        emit AssertionChecked(id, "balance_delta", string(abi.encodePacked(actor, token)), observed, expectedDelta, ok);
        require(ok, "economic assertion mismatch");
    }
}
