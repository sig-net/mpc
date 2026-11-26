// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

// Local TRE targets for the real-stack ERC20 vault's Tron lend test, deployed through
// java-tron's deploycontract. They expose the ABI the vault's MPC-signed calls use on Tron
// USDT and JustLend V2's USDT vault (jUSDTv2): 18-decimal shares over a 6-decimal asset.

// Tron USDT's return values: transfer moves the tokens yet returns false, while
// transferFrom and approve return true.
contract MidnightVaultTronUsdt is ERC20 {
    constructor(uint256 supply) ERC20("Midnight Vault Tron USDT", "MVUSDT") {
        _mint(msg.sender, supply);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        super.transfer(to, value);
        return false;
    }
}

// OpenZeppelin ERC-4626 with 12 decimals of offset, plus the owner's switches the refusal
// scenarios need: a pause that refuses deposits and redeems, and lending out the idle
// underlying, which stays in totalAssets but caps redeems at the cash left.
contract MidnightVaultTronLend is ERC4626 {
    address public immutable owner;
    bool public paused;
    // Underlying the owner took out with lend and has not repaid.
    uint256 public lent;

    constructor(
        IERC20 underlying
    ) ERC20("Midnight Vault Tron lend", "MVJUSDT") ERC4626(underlying) {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    function setPaused(bool value) external onlyOwner {
        paused = value;
    }

    // Takes `amount` of the idle underlying out, as a borrower would.
    function lend(uint256 amount) external onlyOwner {
        lent += amount;
        _pushAsset(msg.sender, amount);
    }

    // Credits `amount` the owner already transferred back against what it took.
    function repay(uint256 amount) external onlyOwner {
        lent -= amount;
    }

    function totalAssets() public view override returns (uint256) {
        return super.totalAssets() + lent;
    }

    function maxDeposit(address receiver) public view override returns (uint256) {
        return paused ? 0 : super.maxDeposit(receiver);
    }

    function maxMint(address receiver) public view override returns (uint256) {
        return paused ? 0 : super.maxMint(receiver);
    }

    function maxWithdraw(address holder) public view override returns (uint256) {
        return paused ? 0 : Math.min(super.maxWithdraw(holder), _cash());
    }

    function maxRedeem(address holder) public view override returns (uint256) {
        return
            paused
                ? 0
                : Math.min(super.maxRedeem(holder), _convertToShares(_cash(), Math.Rounding.Floor));
    }

    function _decimalsOffset() internal pure override returns (uint8) {
        return 12;
    }

    // OpenZeppelin's _withdraw with the asset pushed by _pushAsset instead of SafeERC20.
    function _withdraw(
        address caller,
        address receiver,
        address holder,
        uint256 assets,
        uint256 shares
    ) internal override {
        if (caller != holder) {
            _spendAllowance(holder, caller, shares);
        }
        _burn(holder, shares);
        _pushAsset(receiver, assets);
        emit Withdraw(caller, receiver, holder, assets, shares);
    }

    function _cash() private view returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    // Tron USDT's transfer returns false on success, which SafeERC20 refuses; only a revert
    // fails here.
    function _pushAsset(address to, uint256 amount) private {
        (bool ok, ) = asset().call(abi.encodeCall(IERC20.transfer, (to, amount)));
        require(ok, "Asset transfer reverted");
    }
}
