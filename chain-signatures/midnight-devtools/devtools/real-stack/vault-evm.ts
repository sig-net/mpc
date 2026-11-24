import { readFileSync } from "node:fs";
import {
  Contract,
  ContractFactory,
  NonceManager,
  Wallet,
  toBeHex,
  type ContractMethod,
  type InterfaceAbi,
  type JsonRpcProvider,
  type Transaction,
  type TransactionReceipt,
} from "ethers";

const ARTIFACTS = new URL(
  "../../../contract-eth/artifacts/contracts/MidnightVaultTargets.sol/",
  import.meta.url,
);

interface Artifact {
  abi: InterfaceAbi;
  bytecode: string;
}

function artifact(name: string): Artifact {
  const url = new URL(`${name}.json`, ARTIFACTS);
  try {
    return JSON.parse(readFileSync(url, "utf8")) as Artifact;
  } catch (error) {
    throw new Error(`reading ${url.pathname}; run just build eth`, { cause: error });
  }
}

/** Local stand-ins for the vault's pinned EVM contracts. */
export interface VaultTargets {
  usdc: string;
  output: string;
  stata: string;
  router: string;
}

export class VaultEvm {
  private readonly funder: NonceManager;

  constructor(
    readonly provider: JsonRpcProvider,
    funderKey: string,
  ) {
    this.funder = new NonceManager(new Wallet(funderKey, provider));
  }

  private async deploy(name: string, ...args: unknown[]): Promise<string> {
    const { abi, bytecode } = artifact(name);
    const contract = await new ContractFactory(abi, bytecode, this.funder).deploy(...args);
    await contract.waitForDeployment();
    return contract.getAddress();
  }

  async deployTargets(): Promise<VaultTargets> {
    const usdc = await this.deploy("MidnightVaultToken", "USD Coin", "USDC");
    const output = await this.deploy("MidnightVaultToken", "Swap Output", "OUT");
    const stata = await this.deploy("MidnightVaultStata", usdc);
    const router = await this.deploy("MidnightVaultSwapRouter");
    return { usdc, output, stata, router };
  }

  async fundGas(address: string): Promise<void> {
    await this.provider.send("anvil_setBalance", [address, toBeHex(10n ** 19n)]);
  }

  async mint(token: string, to: string, amount: bigint): Promise<void> {
    const contract = new Contract(token, artifact("MidnightVaultToken").abi, this.funder);
    const sent = await contract.getFunction("mint")(to, amount);
    const receipt = (await sent.wait()) as TransactionReceipt | null;
    if (receipt?.status !== 1) throw new Error(`minting ${token} to ${to} failed`);
  }

  balanceOf(token: string, holder: string): Promise<bigint> {
    return new Contract(token, artifact("MidnightVaultToken").abi, this.provider).getFunction<
      ContractMethod<unknown[], bigint, bigint>
    >("balanceOf")(holder);
  }

  previewRedeem(stata: string, shares: bigint): Promise<bigint> {
    return new Contract(stata, artifact("MidnightVaultStata").abi, this.provider).getFunction<
      ContractMethod<unknown[], bigint, bigint>
    >("previewRedeem")(shares);
  }

  quoteSwap(router: string, amountOut: bigint): Promise<bigint> {
    return new Contract(router, artifact("MidnightVaultSwapRouter").abi, this.provider).getFunction<
      ContractMethod<unknown[], bigint, bigint>
    >("quoteExactOutputSingle")(amountOut);
  }

  /** Broadcasts an MPC-signed transaction and returns its successful receipt. */
  async execute(signed: Transaction): Promise<TransactionReceipt> {
    const sent = await this.provider.broadcastTransaction(signed.serialized);
    const receipt = await sent.wait(1, 120_000);
    if (receipt?.status !== 1) throw new Error(`EVM transaction ${sent.hash} did not succeed`);
    return receipt;
  }

  /** The top-level call's return data, which the MPC decodes. */
  async returnData(hash: string): Promise<string> {
    const trace: unknown = await this.provider.send("debug_traceTransaction", [
      hash,
      { tracer: "callTracer" },
    ]);
    const output = (trace as { output?: unknown }).output;
    if (typeof output !== "string") throw new Error(`no call output traced for ${hash}`);
    return output;
  }
}
