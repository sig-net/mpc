// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal TRC-20 for the live gate on TRE: the acceptance probe
/// transfers one unit to itself and settles on the Transfer event.
/// The mint goes to the deterministic TRE account (private key
/// 0x00...01) regardless of which account runs the deployment.
contract GateToken {
    string public name = "Gate Token";
    string public symbol = "GATE";
    uint8 public decimals = 6;

    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    address public constant TRE_ACCOUNT =
        address(0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf);

    constructor() {
        balanceOf[TRE_ACCOUNT] = 1_000_000;
        emit Transfer(address(0), TRE_ACCOUNT, 1_000_000);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
