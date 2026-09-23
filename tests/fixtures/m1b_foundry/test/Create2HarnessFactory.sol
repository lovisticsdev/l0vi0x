// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {EconHarness} from "./lib/EconHarness.sol";

contract Create2HarnessFactory {
    address public immutable HARNESS_DEPLOYER;

    constructor() {
        HARNESS_DEPLOYER = address(this);
    }

    function deploy(bytes32 salt, bytes memory initCode) public returns (address deployed) {
        assembly {
            deployed := create2(0, add(initCode, 0x20), mload(initCode), salt)
            if iszero(deployed) { revert(0, 0) }
        }
    }

    function createHarness(bytes32 salt) external returns (address harness) {
        bytes memory code = abi.encodePacked(type(EconHarness).creationCode, abi.encode(address(this)));
        return deploy(salt, code);
    }

    function runAttack(
        address harness,
        address pool,
        address oracle,
        address token,
        address actor,
        bytes32 assertionId,
        uint256 expectedDelta
    ) external {
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        (uint256 ethBefore, uint256[] memory balancesBefore) = IEconHarness(harness).snap(actor, tokens);
        uint256 poolTokenBefore = _balanceOf(token, pool);

        // BEGIN ATTACK BODY
        (bool ok,) = oracle.call(abi.encodeWithSignature("setPrice(uint256)", expectedDelta));
        require(ok, "oracle update");
        (ok,) = pool.call(abi.encodeWithSignature("borrow(uint256)", expectedDelta));
        require(ok, "borrow");
        (ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", actor, expectedDelta));
        require(ok, "actor transfer");
        // END ATTACK BODY

        (uint256 ethAfter, uint256[] memory balancesAfter) = IEconHarness(harness).snap(actor, tokens);
        uint256 poolTokenAfter = _balanceOf(token, pool);
        IEconHarness(harness).assertBalanceDelta(
            assertionId,
            actor,
            token,
            balancesBefore[0],
            balancesAfter[0],
            int256(expectedDelta)
        );
        IEconHarness(harness).reportEconomicSnapshot(
            assertionId,
            actor,
            token,
            ethBefore,
            ethAfter,
            balancesBefore[0],
            balancesAfter[0],
            1 ether,
            int256(poolTokenAfter) - int256(poolTokenBefore)
        );
    }

    function _balanceOf(address token, address account) internal view returns (uint256 balance) {
        (bool ok, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", account)
        );
        require(ok && data.length >= 32, "balanceOf");
        balance = abi.decode(data, (uint256));
    }

    function runControl(address harness, address pool, address token, address actor, bytes32 assertionId) external {
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        (uint256 ethBefore, uint256[] memory balancesBefore) = IEconHarness(harness).snap(actor, tokens);
        (bool ok,) = pool.call(abi.encodeWithSignature("borrow(uint256)", 0));
        require(ok, "control borrow");
        (uint256 ethAfter, uint256[] memory balancesAfter) = IEconHarness(harness).snap(actor, tokens);
        bool stateChanged = ethBefore != ethAfter || balancesBefore[0] != balancesAfter[0];
        IEconHarness(harness).reportControl(assertionId, stateChanged);
    }
}

interface IEconHarness {
    function snap(address actor, address[] memory tokens) external view returns (uint256 eth, uint256[] memory tokenBalances);
    function assertBalanceDelta(bytes32 id, address actor, address token, uint256 beforeBal, uint256 afterBal, int256 expectedDelta) external;
    function reportControl(bytes32 id, bool stateChanged) external;
    function reportEconomicSnapshot(bytes32 id, address actor, address token, uint256 nativeBefore, uint256 nativeAfter, uint256 tokenBefore, uint256 tokenAfter, uint256 declaredCapital, int256 protocolAssetsDelta) external;
}
