// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Each target uses the caller fixture's selector while Solidity produces the
// actual ABI return encoding. Values match the pinned SDK conformance vectors.
contract MidnightUint256Output {
    function isEven(uint256) external pure returns (uint256) {
        return 1 << 128;
    }
}

contract MidnightAddressOutput {
    function isEven(uint256) external pure returns (address) {
        return 0x0102030405060708090a0B0c0d0e0f1011121314;
    }
}

contract MidnightTagThenAddressOutput {
    function isEven(uint256) external pure returns (bytes12 tag, address to) {
        tag = bytes12(0xa1a2a3a4a5a6a7a8a9aaabac);
        to = 0x0102030405060708090a0B0c0d0e0f1011121314;
    }
}

// Returns a second word that the single-field output schema does not declare.
contract MidnightTrailingWordOutput {
    function isEven(uint256) external pure returns (bool ok, uint256 extra) {
        ok = true;
        extra = type(uint256).max;
    }
}
