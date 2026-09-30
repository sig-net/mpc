import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { rawTokenType } from "@midnight-ntwrk/compact-runtime";
import { findDeployedContract, type FoundContract } from "@midnight-ntwrk/midnight-js/contracts";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import {
  asciiPadded,
  bytesToHex,
  deriveEvmAddress,
  deriveMidnightResponseKey,
  deserializeEvmOutput,
  hexToBytes,
  requestIdHex,
  respondBidirectionalEventToCircuitInput,
  serializeRespondOutput,
  signetEventSourceFromIndexer,
  SignetRequestResponseReader,
  type RequestIdHex,
  type RespondBidirectionalEvent,
  type Secp256k1Point,
} from "@sig-net/midnight";
import {
  deriveAccountKeys,
  withSyncedWalletFacade,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import { JsonRpcProvider } from "ethers";
import { ledger, pureCircuits } from "./managed/erc20-vault/contract/index.js";
import type { CallPlacement } from "./placement.js";
import {
  buildVaultProviders,
  VAULT_PRIVATE_STATE_ID,
  vaultCompiledContract,
  type VaultContract,
  type VaultProviders,
} from "./vault-contract.js";
import { deployVault } from "./vault-deploy.js";
import { VaultEvm, type VaultTargets } from "./vault-evm.js";

type VaultHandle = FoundContract<VaultContract>;
type VaultLedger = ReturnType<typeof ledger>;

/** The request maps the vault's notifications name, as compiled ledger paths. */
const REQUEST_PATHS = {
  signBidirectionalEventMap: [0, 0],
  depositEventMap: [1, 3],
  swapEventMap: [1, 7],
  supplyEventMap: [1, 11],
  redeemEventMap: [1, 13],
} as const;
type RequestMap = keyof typeof REQUEST_PATHS;

const FLUSH_WIDTH = 20;
const CHAIN_ID = 31337n;
const WITHDRAW_AMOUNT = 100_000n;
const SWAP_AMOUNT_OUT = 1_000_000n;
const SWAP_AMOUNT_IN_MAXIMUM = 1_650_000n;
const SUPPLY_AMOUNT = 1_000_000n;
const DEPOSIT_AMOUNT = WITHDRAW_AMOUNT + SWAP_AMOUNT_IN_MAXIMUM + SUPPLY_AMOUNT;
// Donated to the wrapper before the redeem, so the redeemed assets exceed the shares.
const REDEEM_YIELD = 50_000n;

export interface VaultRunInput {
  config: MidnightNodeConfig;
  artifactDir: string;
  centralAddress: string;
  mpcPublicKey: string;
  evmRpcUrl: string;
  evmFunderKey: string;
  deployerSeed: string;
  userSeed: string;
  userFacade: WalletFacade;
}

export interface VaultOperation {
  operation: string;
  requestId: string;
  /** Placement of the transaction whose singleton call notified the request. */
  placement: CallPlacement[];
  evmTransaction: string;
  evmBlockHeight: number;
  /** Serialized output the attestation signs, hex. */
  output: string;
}

export interface VaultRunResult {
  vaultAddress: string;
  targets: VaultTargets;
  operations: VaultOperation[];
}

interface SentRequest {
  operation: string;
  map: RequestMap;
  requestId: RequestIdHex;
  placement: CallPlacement[];
  signer: string;
}

interface AttestedRequest extends SentRequest {
  evmTransaction: string;
  evmBlockHeight: number;
  decoded: Record<string, unknown>;
  output: Uint8Array;
  event: RespondBidirectionalEvent;
}

const diagnostics = (message: string) => process.stderr.write(`vault: ${message}\n`);

function attestedOf(attested: Map<string, AttestedRequest>, operation: string): AttestedRequest {
  const request = attested.get(operation);
  if (request === undefined) throw new Error(`no attested ${operation}`);
  return request;
}

function padded(keys: readonly Uint8Array[]): Uint8Array[] {
  if (keys.length > FLUSH_WIDTH) throw new Error(`a flush takes at most ${FLUSH_WIDTH} keys`);
  return [...keys, ...Array.from({ length: FLUSH_WIDTH - keys.length }, () => new Uint8Array(32))];
}

async function poll<T>(description: string, read: () => Promise<T | undefined>): Promise<T> {
  const deadline = Date.now() + 480_000;
  while (Date.now() < deadline) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(`timed out waiting for ${description}`);
}

class VaultRun {
  private lastPlacement: CallPlacement[] = [];
  private readonly operations: VaultOperation[] = [];
  private readonly evm: VaultEvm;
  private readonly userSecret: Uint8Array;
  private providers!: VaultProviders;
  private vault!: VaultHandle;
  private vaultAddress!: string;
  private targets!: VaultTargets;
  private responseKey!: Secp256k1Point;
  private vaultEvm!: string;
  private userEvm!: string;

  constructor(private readonly input: VaultRunInput) {
    this.evm = new VaultEvm(
      new JsonRpcProvider(input.evmRpcUrl, undefined, { cacheTimeout: -1 }),
      input.evmFunderKey,
    );
    this.userSecret = hexToBytes(input.userSeed);
  }

  private async readLedger(): Promise<VaultLedger> {
    const state = await this.providers.publicDataProvider.queryContractState(this.vaultAddress);
    if (!state) throw new Error(`no vault state at ${this.vaultAddress}`);
    return ledger(state.data);
  }

  private tokenType(token: string): string {
    return rawTokenType(
      pureCircuits.vaultTokenDomainSeparator(hexToBytes(token)),
      this.vaultAddress,
    );
  }

  private coin(token: string, value: bigint) {
    return { nonce: randomBytes(32), color: hexToBytes(this.tokenType(token)), value };
  }

  private async shieldedBalance(token: string): Promise<bigint> {
    const state = await this.input.userFacade.waitForSyncedState();
    return state.shielded.balances[this.tokenType(token)] ?? 0n;
  }

  // Minted coins reach the wallet once it syncs the settling block.
  private async expectBalance(token: string, expected: bigint): Promise<void> {
    await poll(`shielded balance ${expected} of ${token}`, async () =>
      (await this.shieldedBalance(token)) === expected ? true : undefined,
    );
  }

  private reader(map: RequestMap): SignetRequestResponseReader {
    return new SignetRequestResponseReader({
      requesterContractAddress: this.vaultAddress,
      requesterRequestsPath: REQUEST_PATHS[map],
      signetContractAddress: this.input.centralAddress,
      publicDataProvider: this.providers.publicDataProvider,
      eventSource: signetEventSourceFromIndexer({ queryUrl: this.input.config.indexerUrl }),
    });
  }

  async deployAndInitialise(): Promise<void> {
    const { config } = this.input;
    this.targets = await this.evm.deployTargets();
    const deployerKeys = deriveAccountKeys(this.input.deployerSeed, config.networkId);
    const deployerSecret = hexToBytes(this.input.deployerSeed);
    await withSyncedWalletFacade(deployerKeys, config, async (facade) => {
      const providers = this.providersFor(facade, deployerKeys, "vault-deployer.leveldb");
      diagnostics("deploying the vault");
      this.vaultAddress = await deployVault(
        facade,
        deployerKeys,
        providers.publicDataProvider,
        config.networkId,
        this.input.centralAddress,
        deployerSecret,
      );
      this.responseKey = deriveMidnightResponseKey(this.input.mpcPublicKey, this.vaultAddress);
      this.vaultEvm = deriveEvmAddress(
        this.input.mpcPublicKey,
        this.vaultAddress,
        bytesToHex(asciiPadded("vault", 32)),
      );
      const deployer = await findDeployedContract(providers, {
        contractAddress: this.vaultAddress,
        compiledContract: vaultCompiledContract,
        privateStateId: VAULT_PRIVATE_STATE_ID,
        initialPrivateState: { secretKey: deployerSecret },
      });
      diagnostics("initialising the vault");
      await deployer.callTx.initialise(
        hexToBytes(this.vaultEvm),
        hexToBytes(this.targets.router),
        hexToBytes(this.targets.usdc),
        hexToBytes(this.targets.stata),
        CHAIN_ID,
        this.responseKey,
        1n,
        BigInt(await this.evm.provider.getBlockNumber()),
      );
    });
    this.providers = this.providersFor(
      this.input.userFacade,
      deriveAccountKeys(this.input.userSeed, config.networkId),
      "vault-user.leveldb",
    );
    this.vault = await findDeployedContract(this.providers, {
      contractAddress: this.vaultAddress,
      compiledContract: vaultCompiledContract,
      privateStateId: VAULT_PRIVATE_STATE_ID,
      initialPrivateState: { secretKey: this.userSecret },
    });
    const configured = await this.readLedger();
    if (configured.initialised !== 1n || configured.evmChainId !== CHAIN_ID) {
      throw new Error("the vault did not initialise");
    }
    this.userEvm = deriveEvmAddress(
      this.input.mpcPublicKey,
      this.vaultAddress,
      bytesToHex(pureCircuits.userCommitment(this.userSecret)),
    );
    await this.evm.fundGas(this.vaultEvm);
    await this.evm.fundGas(this.userEvm);
    await this.evm.mint(this.targets.usdc, this.userEvm, DEPOSIT_AMOUNT);
  }

  private providersFor(facade: WalletFacade, keys: AccountKeys, database: string): VaultProviders {
    return buildVaultProviders(
      facade,
      keys,
      this.input.config,
      join(this.input.artifactDir, database),
      (placement) => {
        this.lastPlacement = placement;
      },
    );
  }

  private async flush(): Promise<void> {
    const state = await this.readLedger();
    const unstamped = [...state.pendingVaultRequests]
      .map(([key]) => key)
      .filter((key) => !state.stamps.member(key));
    const seen = [...state.seenEvmHeights].map(([requestId]) => requestId);
    await this.vault.callTx.flush(padded(unstamped), padded(seen.slice(0, FLUSH_WIDTH)));
    const flushed = await this.readLedger();
    if (unstamped.some((key) => !flushed.stamps.member(key))) {
      throw new Error("the flush left a queued request unstamped");
    }
  }

  // Sends one stamped request and identifies it as the single id its map gained.
  private async send(
    operation: string,
    map: RequestMap,
    signer: string,
    submit: () => Promise<unknown>,
  ): Promise<SentRequest> {
    const before = new Set([...(await this.readLedger())[map]].map(([id]) => bytesToHex(id)));
    await submit();
    const added = [...(await this.readLedger())[map]]
      .map(([id]) => bytesToHex(id))
      .filter((id) => !before.has(id));
    const [requestId] = added;
    if (requestId === undefined || added.length !== 1) {
      throw new Error(`${operation} added ${added.length} requests`);
    }
    const placement = this.lastPlacement;
    const phase = placement.some((call) => call.fallibleNotifications.includes(requestId))
      ? "fallible"
      : placement.some((call) => call.guaranteedNotifications.includes(requestId))
        ? "guaranteed"
        : "missing";
    diagnostics(`${operation} notified ${requestId} in the ${phase} transcript`);
    return { operation, map, requestId: requestIdHex(hexToBytes(requestId)), placement, signer };
  }

  // Waits for every MPC signature, executes the transactions in nonce order, recomputes the
  // output the MPC attests and waits for attestations that verify against the response key.
  private async executeAll(
    requests: readonly SentRequest[],
    schemas: (request: SentRequest) => [Uint8Array, Uint8Array],
    beforeExecution?: () => Promise<void>,
  ): Promise<Map<string, AttestedRequest>> {
    const signed = await Promise.all(
      requests.map(async (request) => ({
        request,
        transaction: await poll(`${request.operation} signature`, () =>
          this.reader(request.map).getSignedEvmTransaction(request.requestId, request.signer),
        ),
      })),
    );
    await beforeExecution?.();
    signed.sort((a, b) =>
      a.request.signer === b.request.signer
        ? a.transaction.nonce - b.transaction.nonce
        : a.request.signer.localeCompare(b.request.signer),
    );
    const executed = [];
    for (const { request, transaction } of signed) {
      const receipt = await this.evm.execute(transaction);
      const [outputSchema, respondSchema] = schemas(request);
      const decoded = deserializeEvmOutput(outputSchema, await this.evm.returnData(receipt.hash));
      if ("success" in decoded && decoded.success !== true) {
        throw new Error(`${request.operation} returned false`);
      }
      diagnostics(`${request.operation} executed in EVM block ${receipt.blockNumber}`);
      executed.push({
        ...request,
        evmTransaction: receipt.hash,
        evmBlockHeight: receipt.blockNumber,
        decoded,
        output: serializeRespondOutput(respondSchema, decoded),
      });
    }
    const attested = new Map<string, AttestedRequest>();
    for (const request of executed) {
      const event = await poll(`${request.operation} attestation`, () =>
        this.reader(request.map).getVerifiedRespondBidirectionalEvent(
          request.requestId,
          request.output,
          this.responseKey,
        ),
      );
      if (event.blockHeight !== BigInt(request.evmBlockHeight)) {
        throw new Error(`${request.operation} attested height ${event.blockHeight}`);
      }
      attested.set(request.operation, { ...request, event });
      this.operations.push({
        operation: request.operation,
        requestId: request.requestId,
        placement: request.placement,
        evmTransaction: request.evmTransaction,
        evmBlockHeight: request.evmBlockHeight,
        output: bytesToHex(request.output),
      });
    }
    return attested;
  }

  private async removed(map: RequestMap, requestId: RequestIdHex): Promise<void> {
    if ((await this.readLedger())[map].member(hexToBytes(requestId))) {
      throw new Error(`${map} still holds the settled request ${requestId}`);
    }
  }

  async run(): Promise<VaultRunResult> {
    const transferSchemas = (): [Uint8Array, Uint8Array] => [
      pureCircuits.vaultResponseSchema(),
      pureCircuits.vaultResponseSchema(),
    ];
    const { usdc, output, stata, router } = this.targets;
    const wallet = this.input.userFacade;

    // One deposit funds every later leg; both approvals ride the same flush.
    diagnostics("queueing the deposit and approvals");
    const depositNonce = BigInt(await this.evm.provider.getTransactionCount(this.userEvm));
    const depositKey = pureCircuits.refundCommitment(
      this.userSecret,
      pureCircuits.depositBinder(depositNonce),
    );
    await this.vault.callTx.startDeposit(depositNonce, 100_000n, 30_000_000_000n, 1_000_000_000n, {
      erc20Address: hexToBytes(usdc),
      amount: DEPOSIT_AMOUNT,
    });
    await this.vault.callTx.approveRouter(hexToBytes(usdc));
    await this.vault.callTx.approveStata();
    await this.flush();
    const opening = [
      await this.send("deposit", "depositEventMap", this.userEvm, () =>
        this.vault.callTx.sendDeposit(depositKey),
      ),
      await this.send("approveRouter", "signBidirectionalEventMap", this.vaultEvm, () =>
        this.vault.callTx.sendApproveRouter(pureCircuits.approveRouterBinder(hexToBytes(usdc))),
      ),
      await this.send("approveStata", "signBidirectionalEventMap", this.vaultEvm, () =>
        this.vault.callTx.sendApproveStata(pureCircuits.approveStataBinder()),
      ),
    ];
    const vaultBefore = await this.evm.balanceOf(usdc, this.vaultEvm);
    const deposit = attestedOf(await this.executeAll(opening, transferSchemas), "deposit");
    if ((await this.evm.balanceOf(usdc, this.vaultEvm)) - vaultBefore !== DEPOSIT_AMOUNT) {
      throw new Error("the deposit did not move the ERC20 into the vault account");
    }
    await this.vault.callTx.completeDeposit(
      respondBidirectionalEventToCircuitInput(deposit.event),
      deposit.output,
      randomBytes(32),
      {
        is_some: false,
        value: {
          is_left: true,
          left: { bytes: new Uint8Array(32) },
          right: { bytes: new Uint8Array(32) },
        },
      },
    );
    await this.removed("depositEventMap", deposit.requestId);
    await this.expectBalance(usdc, DEPOSIT_AMOUNT);

    diagnostics("queueing the withdraw, swap and supply");
    const withdrawKey = randomBytes(32);
    const swapKey = randomBytes(32);
    const supplyKey = randomBytes(32);
    await this.vault.callTx.startWithdraw(
      {
        erc20Address: hexToBytes(usdc),
        amount: WITHDRAW_AMOUNT,
        destEvmAddress: hexToBytes(this.userEvm),
      },
      this.coin(usdc, WITHDRAW_AMOUNT),
      withdrawKey,
    );
    // Each surrendered coin is split from the wallet's change of the previous one.
    await wallet.waitForSyncedState();
    await this.vault.callTx.startSwap(
      {
        tokenIn: hexToBytes(usdc),
        tokenOut: hexToBytes(output),
        fee: 500n,
        amountOut: SWAP_AMOUNT_OUT,
        amountInMaximum: SWAP_AMOUNT_IN_MAXIMUM,
      },
      this.coin(usdc, SWAP_AMOUNT_IN_MAXIMUM),
      swapKey,
    );
    await wallet.waitForSyncedState();
    await this.vault.callTx.startSupply(
      { amount: SUPPLY_AMOUNT },
      this.coin(usdc, SUPPLY_AMOUNT),
      supplyKey,
    );
    await this.flush();
    const legs = [
      await this.send("withdraw", "signBidirectionalEventMap", this.vaultEvm, () =>
        this.vault.callTx.sendWithdraw(withdrawKey),
      ),
      await this.send("swap", "swapEventMap", this.vaultEvm, () =>
        this.vault.callTx.sendSwap(swapKey),
      ),
      await this.send("supply", "supplyEventMap", this.vaultEvm, () =>
        this.vault.callTx.sendSupply(supplyKey),
      ),
    ];
    const userBefore = await this.evm.balanceOf(usdc, this.userEvm);
    const settled = await this.executeAll(legs, (request) =>
      request.operation === "swap"
        ? [pureCircuits.swapOutputSchema(), pureCircuits.swapRespondSchema()]
        : request.operation === "supply"
          ? [pureCircuits.supplyOutputSchema(), pureCircuits.supplyRespondSchema()]
          : transferSchemas(),
    );
    const withdraw = attestedOf(settled, "withdraw");
    const swap = attestedOf(settled, "swap");
    const supply = attestedOf(settled, "supply");
    if ((await this.evm.balanceOf(usdc, this.userEvm)) - userBefore !== WITHDRAW_AMOUNT) {
      throw new Error("the withdraw did not pay the destination");
    }
    const amountIn = await this.evm.quoteSwap(router, SWAP_AMOUNT_OUT);
    if (swap.decoded.amountIn !== amountIn) throw new Error("the swap attested another amountIn");
    const shares = supply.decoded.shares;
    if (shares !== SUPPLY_AMOUNT) throw new Error(`the supply attested ${String(shares)} shares`);
    await this.vault.callTx.completeWithdraw(
      respondBidirectionalEventToCircuitInput(withdraw.event),
      withdraw.output,
      randomBytes(32),
    );
    await this.vault.callTx.completeSwap(
      respondBidirectionalEventToCircuitInput(swap.event),
      swap.output,
      randomBytes(32),
      randomBytes(32),
    );
    await this.vault.callTx.completeSupply(
      respondBidirectionalEventToCircuitInput(supply.event),
      supply.output,
      randomBytes(32),
    );
    await this.removed("signBidirectionalEventMap", withdraw.requestId);
    await this.removed("swapEventMap", swap.requestId);
    await this.removed("supplyEventMap", supply.requestId);
    const usdcAfterLegs = DEPOSIT_AMOUNT - WITHDRAW_AMOUNT - amountIn - SUPPLY_AMOUNT;
    await this.expectBalance(usdc, usdcAfterLegs);
    await this.expectBalance(output, SWAP_AMOUNT_OUT);
    await this.expectBalance(stata, SUPPLY_AMOUNT);

    diagnostics("queueing the redeem");
    const redeemKey = randomBytes(32);
    await this.vault.callTx.startRedeem(
      { shares: SUPPLY_AMOUNT },
      this.coin(stata, SUPPLY_AMOUNT),
      redeemKey,
    );
    await this.flush();
    const redeemSent = await this.send("redeem", "redeemEventMap", this.vaultEvm, () =>
      this.vault.callTx.sendRedeem(redeemKey),
    );
    let assets = 0n;
    const redeem = attestedOf(
      await this.executeAll(
        [redeemSent],
        () => [pureCircuits.redeemOutputSchema(), pureCircuits.redeemRespondSchema()],
        async () => {
          await this.evm.mint(usdc, stata, REDEEM_YIELD);
          assets = await this.evm.previewRedeem(stata, SUPPLY_AMOUNT);
        },
      ),
      "redeem",
    );
    if (assets <= SUPPLY_AMOUNT || redeem.decoded.assets !== assets) {
      throw new Error(`the redeem attested ${String(redeem.decoded.assets)}, expected ${assets}`);
    }
    await this.vault.callTx.completeRedeem(
      respondBidirectionalEventToCircuitInput(redeem.event),
      redeem.output,
      randomBytes(32),
    );
    await this.removed("redeemEventMap", redeem.requestId);
    await this.expectBalance(usdc, usdcAfterLegs + assets);
    await this.expectBalance(stata, 0n);

    return { vaultAddress: this.vaultAddress, targets: this.targets, operations: this.operations };
  }

  close(): void {
    this.evm.provider.destroy();
  }
}

/** Deploys the vault against local EVM targets and runs every request kind it sends. */
export async function runVault(input: VaultRunInput): Promise<VaultRunResult> {
  const run = new VaultRun(input);
  try {
    await run.deployAndInitialise();
    return await run.run();
  } finally {
    run.close();
  }
}
