// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Each target uses the caller fixture's selector while Solidity produces the
// actual ABI return encoding. Values match the pinned SDK conformance vectors.
contract MidnightStringOutput {
    function isEven(uint256) external pure returns (string memory) {
        return unicode"Midnight 🌙";
    }
}

contract MidnightBytesOutput {
    function isEven(uint256 variant) external pure returns (bytes memory) {
        if (variant == 0) return hex"deadbeef00";
        if (variant == 1) return hex"deadbeef00010203";
        require(variant == 2, "Unknown fixture variant");
        return hex"";
    }
}

contract MidnightArrayOutput {
    function isEven(uint256) external pure returns (uint64[] memory values) {
        values = new uint64[](2);
        values[0] = 7;
        values[1] = 8;
    }
}
