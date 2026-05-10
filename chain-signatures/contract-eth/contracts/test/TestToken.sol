// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// Minimal ERC20 used by the Canton MPC integration test to verify on-chain
/// state changes after MPC-signed transactions execute on Anvil. `mint` is
/// permissionless because the test harness needs to pre-fund MPC-derived
/// senders without an admin key.
contract TestToken is ERC20 {
    constructor() ERC20("CantonTest", "CTST") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
