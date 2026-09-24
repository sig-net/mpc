import assert from "node:assert/strict";
import {
  AbiCoder,
  Contract,
  type ContractMethod,
  type ContractTransactionResponse,
  type JsonRpcProvider,
  keccak256,
  toBeHex,
} from "ethers";

export const SEPOLIA_USDC = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
export const AAVE_USDC = "0x94a9D9AC8a22534E3FaCa9F4e7F2E2cf85d5E4C8";
export const STATA_USDC = "0x8A88124522dbBF1E56352ba3DE1d9F78C143751e";
export const UNISWAP_ROUTER = "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E";
const QUOTER = "0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3";
const AAVE_CONFIGURATOR = "0x7Ee60D184C24Ef7AfC1Ec7Be59A0f448A0abd138";
const AAVE_ADMIN = "0xfA0e305E0f46AB04f00ae6b5f4560d61a2183E00";
const USER_BALANCE = 100_000_000n;
const ONE_ETH = toBeHex(10n ** 18n);

export function erc20Balance(
  provider: JsonRpcProvider,
  token: string,
  holder: string,
): Promise<bigint> {
  return new Contract(
    token,
    ["function balanceOf(address) view returns (uint256)"],
    provider,
  ).getFunction<ContractMethod<unknown[], bigint, bigint>>("balanceOf")(holder);
}

// Probes restore every candidate, including when the balance read throws. The caller's provider
// disables caching because these storage writes do not advance the block.
async function dealToken(provider: JsonRpcProvider, token: string, holder: string): Promise<void> {
  const abi = AbiCoder.defaultAbiCoder();
  const current = await erc20Balance(provider, token, holder);
  const sentinel = current === 1_337_733_113_377_331n ? current + 1n : 1_337_733_113_377_331n;
  for (let slot = 0; slot < 64; slot++) {
    const candidates = [
      keccak256(abi.encode(["address", "uint256"], [holder, slot])),
      keccak256(abi.encode(["uint256", "address"], [slot, holder])),
    ];
    for (const location of candidates) {
      const original = await provider.getStorage(token, location);
      let matched: boolean;
      try {
        await provider.send("anvil_setStorageAt", [token, location, toBeHex(sentinel, 32)]);
        matched = (await erc20Balance(provider, token, holder)) === sentinel;
      } finally {
        await provider.send("anvil_setStorageAt", [token, location, original]);
      }
      if (!matched) continue;
      await provider.send("anvil_setStorageAt", [token, location, toBeHex(USER_BALANCE, 32)]);
      assert.equal(await erc20Balance(provider, token, holder), USER_BALANCE);
      return;
    }
  }
  throw new Error(`No balance mapping found for ${token} in slots 0..63`);
}

export async function fundFork(
  provider: JsonRpcProvider,
  evmRpcUrl: string,
  user: string,
  vault: string,
): Promise<void> {
  const url = new URL(evmRpcUrl);
  assert(["http:", "https:"].includes(url.protocol), "Fork RPC must use HTTP(S)");
  assert(["127.0.0.1", "localhost", "[::1]"].includes(url.hostname), "Fork RPC must be local");
  const clientVersion: unknown = await provider.send("web3_clientVersion", []);
  assert(typeof clientVersion === "string" && /anvil/i.test(clientVersion), "Fork must be Anvil");
  assert.equal((await provider.getNetwork()).chainId, 31337n, "Fork must use chain ID 31337");
  for (const address of [SEPOLIA_USDC, AAVE_USDC, STATA_USDC, UNISWAP_ROUTER, QUOTER]) {
    assert.notEqual(await provider.getCode(address), "0x", `Missing fork contract ${address}`);
  }

  await provider.send("anvil_setBalance", [user, ONE_ETH]);
  await provider.send("anvil_setBalance", [vault, ONE_ETH]);
  await dealToken(provider, SEPOLIA_USDC, user);
  await dealToken(provider, AAVE_USDC, user);
  await provider.send("anvil_setBalance", [AAVE_ADMIN, ONE_ETH]);
  await provider.send("anvil_impersonateAccount", [AAVE_ADMIN]);
  try {
    const configurator = new Contract(
      AAVE_CONFIGURATOR,
      ["function setSupplyCap(address asset, uint256 newSupplyCap)"],
      await provider.getSigner(AAVE_ADMIN),
    );
    const tx = await configurator.getFunction<
      ContractMethod<unknown[], void, ContractTransactionResponse>
    >("setSupplyCap")(AAVE_USDC, 0n);
    assert.equal((await tx.wait())?.status, 1, "Aave supply-cap update failed");
  } finally {
    await provider.send("anvil_stopImpersonatingAccount", [AAVE_ADMIN]);
  }
}

export async function quoteSwap(
  provider: JsonRpcProvider,
  tokenOut: string,
  fee: bigint,
  amountOut: bigint,
): Promise<bigint> {
  const quoter = new Contract(
    QUOTER,
    [
      "function quoteExactOutputSingle((address tokenIn,address tokenOut,uint256 amount,uint24 fee,uint160 sqrtPriceLimitX96)) returns (uint256 amountIn,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)",
    ],
    provider,
  );
  const [amountIn] = await quoter
    .getFunction<ContractMethod<unknown[], [bigint, bigint, bigint, bigint]>>(
      "quoteExactOutputSingle",
    )
    .staticCall([SEPOLIA_USDC, tokenOut, amountOut, fee, 0n]);
  assert(amountIn > 0n, "Swap quote must require a positive input amount");
  return (amountIn * 110n + 99n) / 100n;
}
