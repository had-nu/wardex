// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

contract ProvenanceAnchor {
    // Mapping of manifestRootHash to block.timestamp
    mapping(bytes32 => uint256) public proofs;

    event Anchored(bytes32 indexed manifestHash, uint256 timestamp);

    function anchor(bytes32 manifestHash) external {
        require(proofs[manifestHash] == 0, "Already anchored");
        proofs[manifestHash] = block.timestamp;
        emit Anchored(manifestHash, block.timestamp);
    }
}
