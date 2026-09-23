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
    event AssertionContext(bytes32 indexed id, address actor, address token);

    event ControlObserved(bytes32 indexed id, bool stateChanged);

    event EconomicSnapshot(
        bytes32 indexed id,
        address actor,
        address token,
        uint256 nativeBefore,
        uint256 nativeAfter,
        uint256 tokenBefore,
        uint256 tokenAfter,
        uint256 declaredCapital,
        int256 protocolAssetsDelta
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
        emit AssertionContext(id, actor, token);
        emit AssertionChecked(id, "balance_delta", "balance_delta", observed, expectedDelta, ok);
        require(ok, "economic assertion mismatch");
    }

    function reportControl(bytes32 id, bool stateChanged) external onlyWrapper {
        emit ControlObserved(id, stateChanged);
    }

    function reportEconomicSnapshot(
        bytes32 id,
        address actor,
        address token,
        uint256 nativeBefore,
        uint256 nativeAfter,
        uint256 tokenBefore,
        uint256 tokenAfter,
        uint256 declaredCapital,
        int256 protocolAssetsDelta
    ) external onlyWrapper {
        emit EconomicSnapshot(id, actor, token, nativeBefore, nativeAfter, tokenBefore, tokenAfter, declaredCapital, protocolAssetsDelta);
    }
}
