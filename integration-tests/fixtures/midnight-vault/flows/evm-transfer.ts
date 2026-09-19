// EVM value helpers shared by the vault flows.

// EIP-1559 gas parameters for the ERC20 transfers the MPC signs. An ERC20
// transfer costs ~50-65k gas; the fee caps are generous.
// Double duty: the gas envelope the deposit flow CHOOSES (the caller's
// account pays those), and the TS mirror of the envelope the CONTRACT FIXES
// for withdrawals (the vault account pays those) — the values MUST stay in
// lockstep with withdraw in erc20-vault.compact, or the withdraw
// expected-record check fails.

/**
 * The ERC20 `transfer(address,uint256)` selector, as broadcast (big-endian).
 * Application-level (this example's vault moves ERC20s) — the in-circuit twin
 * is the literal `Bytes [0xa9, 0x05, 0x9c, 0xbb]` in erc20-vault.compact.
 */
export const ERC20_TRANSFER_SELECTOR = new Uint8Array([0xa9, 0x05, 0x9c, 0xbb]);

/** Gas ceiling of an MPC-signed ERC20 transfer. */
export const ERC20_TRANSFER_GAS_LIMIT = 100_000n;

/** Max total fee per gas of an MPC-signed ERC20 transfer, wei (30 gwei). */
export const ERC20_TRANSFER_MAX_FEE_PER_GAS = 30_000_000_000n;

/** Max priority fee per gas of an MPC-signed ERC20 transfer, wei (1 gwei). */
export const ERC20_TRANSFER_MAX_PRIORITY_FEE_PER_GAS = 1_000_000_000n;
