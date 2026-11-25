// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Pins `contractResult`'s element order on TRE: `f()` is the top
/// frame returning 43; its internal message call `g()` returns 42.
/// A receipt from `f()` must carry the top call's return data in
/// element 0 (§7.5.2.2).
contract RetProbe {
    function g() external returns (uint256) {
        return 42;
    }

    function f() external returns (uint256) {
        return this.g() + 1;
    }
}
