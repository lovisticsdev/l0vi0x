// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

library L0vi0x {
    event TraceMarker(bytes32 indexed id, string label);
    function mark(bytes32 id, string memory label) internal { emit TraceMarker(id, label); }
}
