// Fork-only EVM funding: deal ETH + real USDC to the derived accounts on the local anvil,
// which forks Sepolia so the ERC20 is the real, unmintable USDC. Token balances are dealt by
// writing the holder's slot in the token's balance mapping directly (anvil_setStorageAt, the
// same mechanism as foundry's `deal`), so dealing needs no funded source account and repeated
// redeploy campaigns can never exhaust one. On any other node the accounts are funded by hand.
import { AAVE_USDC } from "../contract/src/index.ts";
import type { ContractWriteMethod } from "../test-harness/evm.ts";
import { requireEnv } from "../test-harness/e2e-env.ts";
import { ethers } from "ethers";

import { isAnvil } from "./evm-anvil.ts";

/** Real Sepolia USDC (the swap suite's tokenIn), also present on a Sepolia fork. */
export const SEPOLIA_USDC = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
// Aave v3 Sepolia PoolConfigurator + a pool admin: the live USDC reserve is supplied ~2x over its
// cap, so maxDeposit is 0 and stataUSDC deposits revert. The fork lifts the cap through these.
const AAVE_POOL_CONFIGURATOR = "0x7Ee60D184C24Ef7AfC1Ec7Be59A0f448A0abd138";
const AAVE_POOL_ADMIN = "0xfA0e305E0f46AB04f00ae6b5f4560d61a2183E00";
const ONE_ETH = "0xDE0B6B3A7640000";
// 100 USDC (6 decimals): far above every suite's small deposits combined.
const USER_USDC = 100_000_000n;

const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];

const readBalance = (
  provider: ethers.JsonRpcProvider,
  token: string,
  holder: string,
): Promise<bigint> =>
  new ethers.Contract(token, ERC20_ABI, provider).getFunction("balanceOf")(
    holder,
  ) as Promise<bigint>;

/**
 * Find the storage location of `holder`'s entry in `token`'s balance mapping by probing: for
 * each candidate mapping slot, write a sentinel to the location that slot implies, check whether
 * `balanceOf(holder)` reads it back, and restore the original word either way. Tries the
 * Solidity mapping layout (`keccak256(holder ++ slot)`) and the Vyper layout
 * (`keccak256(slot ++ holder)`) for each slot. Works through proxies, since the probe targets
 * the address `balanceOf` is called on, which is where a proxy keeps its storage.
 *
 * @param provider - The fork's JSON-RPC provider (anvil with cheatcodes).
 * @param token - The ERC20 token contract.
 * @param holder - The account whose balance location is sought.
 * @returns The 32-byte storage location of the holder's balance.
 * @throws {Error} If no slot in 0..63 maps to `balanceOf` (a non-standard balance layout).
 */
async function findBalanceLocation(
  provider: ethers.JsonRpcProvider,
  token: string,
  holder: string,
): Promise<string> {
  const abi = ethers.AbiCoder.defaultAbiCoder();
  const current = await readBalance(provider, token, holder);
  const sentinel = current === 1_337_733_113_377_331n ? current + 1n : 1_337_733_113_377_331n;
  const sentinelWord = ethers.toBeHex(sentinel, 32);

  for (let slot = 0; slot < 64; slot++) {
    const candidates = [
      ethers.keccak256(abi.encode(["address", "uint256"], [holder, slot])),
      ethers.keccak256(abi.encode(["uint256", "address"], [slot, holder])),
    ];
    for (const location of candidates) {
      const original = await provider.getStorage(token, location);
      await provider.send("anvil_setStorageAt", [token, location, sentinelWord]);
      const observed = await readBalance(provider, token, holder);
      await provider.send("anvil_setStorageAt", [token, location, original]);
      if (observed === sentinel) return location;
    }
  }
  throw new Error(
    `no balance mapping slot found for ${token} in slots 0..63: the token has a non-standard ` +
      `balance layout, so it cannot be dealt by storage write`,
  );
}

/**
 * Set `to`'s balance of `token` to `amount` on the fork by writing the balance mapping slot
 * directly. Total supply is left untouched, exactly like foundry's `deal`, which is irrelevant
 * on a throwaway fork. Setting the balance outright makes dealing idempotent across setup
 * reruns and independent of any source account's balance.
 *
 * @param provider - The fork's JSON-RPC provider (anvil with cheatcodes).
 * @param token - The ERC20 token contract.
 * @param to - The account whose balance is set.
 * @param amount - The base-unit balance to set.
 * @throws {Error} If the balance read back after the write does not equal `amount`.
 */
async function dealErc20(
  provider: ethers.JsonRpcProvider,
  token: string,
  to: string,
  amount: bigint,
): Promise<void> {
  const location = await findBalanceLocation(provider, token, to);
  await provider.send("anvil_setStorageAt", [token, location, ethers.toBeHex(amount, 32)]);
  const observed = await readBalance(provider, token, to);
  if (observed !== amount) {
    throw new Error(
      `dealt ${String(amount)} of ${token} to ${to} but balanceOf reads ${String(observed)}`,
    );
  }
}

/**
 * Deal ETH (+ optional USDC / Aave USDC) to `to` on the fork: anvil setBalance + balance-slot
 * writes. Token amounts SET the balance (idempotent), never add to it.
 *
 * @param provider - The fork's JSON-RPC provider (anvil with cheatcodes).
 * @param to - The recipient address.
 * @param usdc - Circle USDC base units to deal (0 deals none).
 * @param aaveUsdc - Aave USDC base units to deal (0 deals none); the lending suite's underlying.
 */
export async function dealFork(
  provider: ethers.JsonRpcProvider,
  to: string,
  usdc: bigint,
  aaveUsdc = 0n,
): Promise<void> {
  await provider.send("anvil_setBalance", [to, ONE_ETH]);
  if (usdc > 0n) await dealErc20(provider, SEPOLIA_USDC, to, usdc);
  if (aaveUsdc > 0n) await dealErc20(provider, AAVE_USDC, to, aaveUsdc);
}

/**
 * Lift the Aave USDC supply cap on the fork so stataUSDC deposits are accepted. The live Sepolia
 * reserve is supplied ~2x over its 2B cap, so Aave's maxDeposit is 0 and every deposit reverts.
 * Impersonate a pool admin and set the cap to 0, which Aave treats as no cap.
 *
 * @param provider - The fork's JSON-RPC provider (anvil with cheatcodes).
 */
async function liftAaveUsdcSupplyCap(provider: ethers.JsonRpcProvider): Promise<void> {
  await provider.send("anvil_setBalance", [AAVE_POOL_ADMIN, ONE_ETH]);
  await provider.send("anvil_impersonateAccount", [AAVE_POOL_ADMIN]);
  const configurator = new ethers.Contract(
    AAVE_POOL_CONFIGURATOR,
    ["function setSupplyCap(address asset, uint256 newSupplyCap)"],
    await provider.getSigner(AAVE_POOL_ADMIN),
  );
  await (await configurator.getFunction<ContractWriteMethod>("setSupplyCap")(AAVE_USDC, 0n)).wait();
  await provider.send("anvil_stopImpersonatingAccount", [AAVE_POOL_ADMIN]);
  console.log("lifted Aave USDC supply cap on the fork (stataUSDC deposits now accepted)");
}

/**
 * Setup step: deal the derived EVM accounts their gas + tokens on the fork. The user gets ETH +
 * USDC (the deposit source), and the vault gets ETH (withdraw/approve/swap gas, deposits fund
 * its USDC). Dealing is anvil's `anvil_*` cheatcodes, so on any other node (a real chain
 * behind a public RPC) the step skips and prints what to fund by hand instead: the flows'
 * funding preflights then check those balances before spending.
 *
 * @param env - The suite's env accumulator (reads EVM_RPC_URL, EVM_USER_ADDRESS, EVM_VAULT_ADDRESS).
 * @throws {Error} If the RPC does not answer, or the anvil cheatcalls fail on an anvil that is
 *   not forking Sepolia.
 */
export async function dealForkEvmAccounts(env: NodeJS.ProcessEnv): Promise<void> {
  const rpcUrl = requireEnv(env, "EVM_RPC_URL");
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const user = requireEnv(env, "EVM_USER_ADDRESS");
  const vault = requireEnv(env, "EVM_VAULT_ADDRESS");

  if (!(await isAnvil(rpcUrl))) {
    console.log(`${rpcUrl} is not anvil: no cheatcodes, so nothing is dealt`);
    console.log(" ➜ FUND THE DERIVED ACCOUNTS ON THE REAL CHAIN before the flows run:");
    console.log(
      `   user  ${user}: >= 0.01 ETH (funding reserve) and >= 0.1 of ERC20 ${requireEnv(env, "ERC20_ADDRESS")}`,
    );
    console.log(
      `   vault ${vault}: ETH for withdrawal gas (the withdraw preflight prints the maximum gas fee)`,
    );
    console.log(
      " ➜ 💡 STEP_THROUGH=1 pauses before every step and test, so an attended run can fund them",
    );
    console.log("   here and continue");
    return;
  }

  // Fail loudly BEFORE dealing: if USDC has no code, the EVM is not forking Sepolia (almost
  // always a missing/empty SEPOLIA_FORK_RPC_URL), and the balance-slot probe would fail with an
  // opaque decode error instead of this pointed one.
  if ((await provider.getCode(SEPOLIA_USDC)) === "0x") {
    throw new Error(
      `${SEPOLIA_USDC} has no code on ${rpcUrl}: the EVM is not forking Sepolia. Set ` +
        `SEPOLIA_FORK_RPC_URL (in CI, the caller workflow must also pass \`secrets: inherit\`).`,
    );
  }

  // The lending suite deposits Aave's own USDC (the stataUSDC wrapper's asset()), a different
  // token from Circle's USDC. Deal it only when it forks in: the fork-dependency step that runs
  // next fails the whole pipeline on a fork missing the stataUSDC wrapper this is the asset() of,
  // with an error naming the wrapper.
  const aaveUsdcOnFork = (await provider.getCode(AAVE_USDC)) !== "0x";
  const userAaveUsdc = aaveUsdcOnFork ? USER_USDC : 0n;

  try {
    await dealFork(provider, user, USER_USDC, userAaveUsdc);
    await dealFork(provider, vault, 0n);
    if (aaveUsdcOnFork) await liftAaveUsdcSupplyCap(provider);
  } catch (error) {
    throw new Error(
      `fork dealing failed for ${rpcUrl}: the EVM must be a Sepolia fork with anvil_* cheatcodes`,
      { cause: error },
    );
  }
  console.log(
    `dealt on fork: user ${user} <- 100 USDC${aaveUsdcOnFork ? " + 100 Aave USDC" : ""} + gas; ` +
      `vault ${vault} <- gas`,
  );
}
