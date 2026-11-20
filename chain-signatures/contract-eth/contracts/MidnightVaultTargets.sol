// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Local EVM targets for the real-stack ERC20 vault test. They expose the ABI the vault's
// MPC-signed calls use on Sepolia USDC, Uniswap SwapRouter02 and Aave's stataUSDC.

contract MidnightVaultToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// OpenZeppelin ERC-4626: deposit(uint256,address) and redeem(uint256,address,address).
contract MidnightVaultStata is ERC4626 {
    constructor(IERC20 underlying) ERC20("Midnight Vault stata", "MVSTATA") ERC4626(underlying) {}
}

// SwapRouter02's exactOutputSingle at a fixed price of 3/2 tokenIn per tokenOut, rounded up.
contract MidnightVaultSwapRouter {
    struct ExactOutputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountOut;
        uint256 amountInMaximum;
        uint160 sqrtPriceLimitX96;
    }

    function quoteExactOutputSingle(uint256 amountOut) public pure returns (uint256 amountIn) {
        amountIn = (amountOut * 3 + 1) / 2;
    }

    function exactOutputSingle(
        ExactOutputSingleParams calldata params
    ) external returns (uint256 amountIn) {
        amountIn = quoteExactOutputSingle(params.amountOut);
        require(amountIn <= params.amountInMaximum, "Too much requested");
        require(
            IERC20(params.tokenIn).transferFrom(msg.sender, address(this), amountIn),
            "Input transfer failed"
        );
        MidnightVaultToken(params.tokenOut).mint(params.recipient, params.amountOut);
    }
}
