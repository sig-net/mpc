import { readFile } from "node:fs/promises";
import {
  bytesToHex,
  evmAddressAbiWord,
  getSolidifiedTronTransactionInfo,
  hexToBytes,
  numericAbiWord,
  tronAddressFromEvm,
  type TronTransactionInfo,
} from "@sig-net/midnight";
import { computeAddress, SigningKey } from "ethers";

// The lend targets' compiled hardhat artifacts, committed beside their source.
const LEND_ARTIFACTS = new URL("../../../../integration-tests/fixtures/evm/", import.meta.url);

// What the funder's own transactions may burn; TRE prices energy, so the deploy needs room.
const FUNDER_FEE_LIMIT = 1_000_000_000;
const RECEIPT_TIMEOUT_MS = 120_000;
// TRE packs a block only when it holds a transaction, so a pusher keeps the chain moving
// while the MPC waits for receipts.
const PUSHER_INTERVAL_MS = 2_000;
const PUSHER_SINK = tronAddressFromEvm("0x000000000000000000000000000000000000dEaD");

interface UnsignedTronTransaction {
  txID: string;
  raw_data: unknown;
  raw_data_hex: string;
}

interface BuildAnswer extends Partial<UnsignedTronTransaction> {
  transaction?: UnsignedTronTransaction;
  contract_address?: string;
}

interface BroadcastAnswer {
  result?: boolean;
  code?: string;
  message?: string;
}

/** A contract deploycontract takes: its `name`, `abi` and creation `bytecode`. */
export interface TronArtifact {
  name: string;
  abi: unknown[];
  bytecode: string;
}

/** Reads a `{ name, abi, bytecode }` artifact. */
export async function readTronArtifact(path: string): Promise<TronArtifact> {
  return JSON.parse(await readFile(path, "utf8")) as TronArtifact;
}

/** Reads one of the lend targets' hardhat artifacts: `{ contractName, abi, bytecode }`. */
export async function readLendArtifact(contractName: string): Promise<TronArtifact> {
  const url = new URL(`${contractName}.json`, LEND_ARTIFACTS);
  let text: string;
  try {
    text = await readFile(url, "utf8");
  } catch (error) {
    throw new Error(`reading ${url.pathname}`, { cause: error });
  }
  const artifact = JSON.parse(text) as Omit<TronArtifact, "name">;
  return { name: contractName, abi: artifact.abi, bytecode: artifact.bytecode };
}

/** What a solidified receipt says the transaction cost. */
export interface TronCost {
  /** `receipt.result`: SUCCESS, REVERT, OUT_OF_ENERGY, ... */
  result: string;
  energy: number;
  /** Sun burned in total. */
  fee: number;
}

interface ReceiptBody {
  receipt?: { energy_usage_total?: number };
}

/** The result, energy and burned sun of a solidified receipt. */
export function tronCost(receipt: TronTransactionInfo): TronCost {
  const body = receipt.body as ReceiptBody;
  return {
    result: receipt.receiptResult ?? receipt.result ?? "SUCCESS",
    energy: body.receipt?.energy_usage_total ?? 0,
    fee: Number(receipt.fee),
  };
}

/**
 * A TRE chain driven from one funded account: TRX and TRC-20 transfers, a token deploy and
 * reads. The MPC-signed request transactions are broadcast through the SDK, not here.
 */
export class TronChain {
  private readonly key: SigningKey;
  /** The funder's 21-byte address. */
  readonly funder: Uint8Array;

  constructor(
    readonly rpcUrl: string,
    funderPrivateKey: string,
  ) {
    this.key = new SigningKey(`0x${funderPrivateKey.replace(/^0x/i, "")}`);
    this.funder = tronAddressFromEvm(computeAddress(this.key.publicKey));
  }

  private async post<T>(path: string, body: object): Promise<T> {
    const response = await fetch(`${this.rpcUrl.replace(/\/+$/, "")}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`Tron ${path} answered ${response.status}: ${text}`);
    return JSON.parse(text) as T;
  }

  // Builds through the node, signs the txID with the funder key and broadcasts.
  private async submit(
    path: string,
    body: object,
  ): Promise<{ txid: Uint8Array; built: BuildAnswer }> {
    const built = await this.post<BuildAnswer>(path, body);
    const transaction = built.transaction ?? built;
    if (
      transaction.txID === undefined ||
      transaction.raw_data === undefined ||
      transaction.raw_data_hex === undefined
    ) {
      throw new Error(`Tron ${path} built no transaction: ${JSON.stringify(built)}`);
    }
    const signature = this.key.sign(`0x${transaction.txID}`);
    const answer = await this.post<BroadcastAnswer>("/wallet/broadcasttransaction", {
      txID: transaction.txID,
      raw_data: transaction.raw_data,
      raw_data_hex: transaction.raw_data_hex,
      signature: [
        `${signature.r.slice(2)}${signature.s.slice(2)}${signature.yParity.toString(16).padStart(2, "0")}`,
      ],
    });
    if (answer.result !== true) {
      throw new Error(`Tron refused ${path}: ${JSON.stringify(answer)}`);
    }
    return { txid: hexToBytes(transaction.txID), built };
  }

  /** Waits for `txid`'s solidified receipt, which is what the MPC reads. */
  async receipt(txid: Uint8Array): Promise<TronTransactionInfo> {
    const deadline = Date.now() + RECEIPT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const receipt = await getSolidifiedTronTransactionInfo(this.rpcUrl, txid);
      if (receipt !== undefined) return receipt;
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
    throw new Error(`Tron transaction ${bytesToHex(txid)} did not solidify`);
  }

  private async succeeded(txid: Uint8Array, what: string): Promise<TronTransactionInfo> {
    const receipt = await this.receipt(txid);
    const result = receipt.receiptResult ?? receipt.result ?? "SUCCESS";
    if (result !== "SUCCESS") throw new Error(`${what} ran ${result}`);
    return receipt;
  }

  /** Sends `amount` sun to the 21-byte `to`. */
  async sendTrx(to: Uint8Array, amount: bigint): Promise<void> {
    const { txid } = await this.submit("/wallet/createtransaction", {
      owner_address: bytesToHex(this.funder),
      to_address: bytesToHex(to),
      amount: Number(amount),
    });
    await this.succeeded(txid, "TRX transfer");
  }

  /**
   * Deploys `artifact` from the funder with the ABI-encoded constructor `parameter`,
   * returning its 21-byte address.
   */
  async deploy(
    artifact: TronArtifact,
    parameter: Uint8Array = new Uint8Array(),
  ): Promise<Uint8Array> {
    const { txid, built } = await this.submit("/wallet/deploycontract", {
      owner_address: bytesToHex(this.funder),
      name: artifact.name,
      abi: JSON.stringify(artifact.abi),
      bytecode: artifact.bytecode.replace(/^0x/i, ""),
      parameter: bytesToHex(parameter),
      call_value: 0,
      fee_limit: FUNDER_FEE_LIMIT,
      consume_user_resource_percent: 100,
      origin_energy_limit: 10_000_000,
    });
    if (built.contract_address === undefined) {
      throw new Error(`deploycontract named no address: ${JSON.stringify(built)}`);
    }
    await this.succeeded(txid, `${artifact.name} deploy`);
    return hexToBytes(built.contract_address);
  }

  /**
   * Calls `selector` on the 21-byte `contract` from the funder with the ABI-encoded
   * `parameter`, and waits for it to succeed.
   */
  async trigger(
    contract: Uint8Array,
    selector: string,
    parameter: Uint8Array,
  ): Promise<TronTransactionInfo> {
    const { txid } = await this.submit("/wallet/triggersmartcontract", {
      owner_address: bytesToHex(this.funder),
      contract_address: bytesToHex(contract),
      function_selector: selector,
      parameter: bytesToHex(parameter),
      fee_limit: FUNDER_FEE_LIMIT,
      call_value: 0,
    });
    return this.succeeded(txid, selector);
  }

  /** Transfers `amount` of the 21-byte `token` from the funder to the 21-byte `to`. */
  async sendToken(token: Uint8Array, to: Uint8Array, amount: bigint): Promise<void> {
    await this.trigger(
      token,
      "transfer(address,uint256)",
      new Uint8Array([...evmAddressAbiWord(to.subarray(1)), ...numericAbiWord(amount)]),
    );
  }

  /** The first word `selector` on the 21-byte `contract` returns to a constant call. */
  async read(
    contract: Uint8Array,
    selector: string,
    parameter: Uint8Array = new Uint8Array(),
  ): Promise<bigint> {
    const answer = await this.post<{ constant_result?: string[] }>(
      "/wallet/triggerconstantcontract",
      {
        owner_address: bytesToHex(this.funder),
        contract_address: bytesToHex(contract),
        function_selector: selector,
        parameter: bytesToHex(parameter),
      },
    );
    const word = answer.constant_result?.[0];
    if (word === undefined || word === "") {
      throw new Error(`${selector} returned ${JSON.stringify(answer)}`);
    }
    return BigInt(`0x${word}`);
  }

  /** The TRC-20 balance of the 21-byte `owner`. */
  async balanceOf(token: Uint8Array, owner: Uint8Array): Promise<bigint> {
    return this.read(token, "balanceOf(address)", evmAddressAbiWord(owner.subarray(1)));
  }

  /** The solidified head's number. */
  async solidifiedHeight(): Promise<bigint> {
    const block = await this.post<{ block_header?: { raw_data?: { number?: number } } }>(
      "/walletsolidity/getnowblock",
      {},
    );
    return BigInt(block.block_header?.raw_data?.number ?? 0);
  }

  /** Runs `body` while one-sun transfers keep TRE packing blocks. */
  async withBlocks<T>(body: () => Promise<T>): Promise<T> {
    let running = true;
    const pusher = (async () => {
      while (running) {
        await this.sendTrx(PUSHER_SINK, 1n).catch((error: unknown) => {
          process.stderr.write(`vault: Tron block pusher: ${String(error)}\n`);
        });
        await new Promise((resolve) => setTimeout(resolve, PUSHER_INTERVAL_MS));
      }
    })();
    try {
      return await body();
    } finally {
      running = false;
      await pusher;
    }
  }
}
