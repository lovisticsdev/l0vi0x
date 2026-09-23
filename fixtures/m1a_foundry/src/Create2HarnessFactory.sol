// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface IWitnessHarness {
    function check(
        bytes32 id,
        address actor,
        string calldata targetName,
        int256 expected
    ) external;
}

contract Create2HarnessFactory {
    event Deployed(
        address indexed deployed,
        bytes32 indexed salt,
        bytes32 initCodeHash
    );

    function deploy(
        bytes32 salt,
        bytes memory initCode
    ) external returns (address deployed) {
        assembly {
            deployed := create2(
                0,
                add(initCode, 0x20),
                mload(initCode),
                salt
            )
        }
        require(deployed != address(0), "create2 failed");
        emit Deployed(deployed, salt, keccak256(initCode));
    }

    function check(
        address harness,
        bytes32 id,
        address actor,
        string calldata targetName,
        int256 expected
    ) external {
        IWitnessHarness(harness).check(
            id,
            actor,
            targetName,
            expected
        );
    }
}