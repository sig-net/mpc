// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

contract ChainSignaturesProxyAdmin is ProxyAdmin {
    constructor(address initialOwner) ProxyAdmin(initialOwner) {}
}