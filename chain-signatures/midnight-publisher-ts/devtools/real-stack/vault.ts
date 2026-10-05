import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { rawTokenType } from "@midnight-ntwrk/compact-runtime";
import {
  createCallTxOptions,
  createUnprovenCallTx,
  findDeployedContract,
  submitTx,
  type FoundContract,
} from "@midnight-ntwrk/midnight-js/contracts";
import {
  encodeContractKeyLocation,
  hashVerifierKey,
  SucceedEntirely,
} from "@midnight-ntwrk/midnight-js/types";
import {
  communicationCommitmentRandomness,
  ContractCallPrototype,
  ContractState,
  Intent,
  Transaction,
} from "@midnightntwrk/ledger-v9";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import {
  deriveAccountKeys,
  withSyncedWalletFacade,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
// The vault is written against @sig-net/midnight 0.24.0-rc.10, installed under this alias.
import {
  asciiPadded,
  bytesToHex,
  deriveEvmAddress,
  deriveMidnightResponseKey,
  deserializeEvmOutput,
  EvmTraceOutputKind,
  executedEvmRespondOutput,
  hexToBytes,
  requestIdHex,
  respondBidirectionalEventToCircuitInput,
  signetEventSourceFromIndexer,
  SignetRequestResponseReader,
  type RequestIdHex,
  type RespondBidirectionalEvent,
  type Secp256k1Point,
} from "@sig-net/midnight-respond-oracle";
import { JsonRpcProvider } from "ethers";
import {
  Action,
  FlushChannel,
  ledger,
  pureCircuits,
  type FlushSlot,
  type GasParams,
} from "./managed/erc20-vault/contract/index.js";
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

/** Each action's request map: its ledger field and compiled ledger path. */
const REQUEST_MAPS = {
  [Action.approve]: { field: "bidirectionalApproveMap", path: [2, 3] },
  [Action.deposit]: { field: "bidirectionalDepositMap", path: [2, 5] },
  [Action.withdraw]: { field: "bidirectionalWithdrawMap", path: [2, 7] },
  [Action.swap]: { field: "bidirectionalSwapMap", path: [2, 9] },
  [Action.supply]: { field: "bidirectionalSupplyMap", path: [2, 11] },
  [Action.redeem]: { field: "bidirectionalRedeemMap", path: [2, 13] },
} as const;
type VaultAction = keyof typeof REQUEST_MAPS;

const FLUSH_WIDTH = 10;
const FLUSH_TTL_MS = 5 * 60_000;
const CHAIN_ID = 31337n;
const DEPOSIT_GAS: GasParams = {
  gasLimit: 100_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
};
const SWAP_FEE = 500n;
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

/** A request its start circuit queued under `inIndex`. */
interface StartedRequest {
  operation: string;
  action: VaultAction;
  inIndex: bigint;
  /** The EVM account the MPC signs the request's transaction with. */
  signer: string;
  outputSchema: Uint8Array;
}

interface SentRequest extends StartedRequest {
  requestId: RequestIdHex;
  placement: CallPlacement[];
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

/** A fresh input buffer index for a start circuit: 64 random bits. */
function newInputIndex(): bigint {
  return randomBytes(8).readBigUInt64BE();
}

// Attestation slots first, so the request slots behind them record those heights as
// their lastSeen, then empty slots to the width.
function flushSlots(inIndexes: readonly bigint[], requestIds: readonly Uint8Array[]): FlushSlot[] {
  if (inIndexes.length + requestIds.length > FLUSH_WIDTH) {
    throw new Error(`a flush takes at most ${String(FLUSH_WIDTH)} items`);
  }
  const empty = new Uint8Array(32);
  return [
    ...requestIds.map((requestId) => ({
      channel: FlushChannel.attestation,
      inIndex: 0n,
      requestId,
    })),
    ...inIndexes.map((inIndex) => ({ channel: FlushChannel.request, inIndex, requestId: empty })),
    ...Array.from({ length: FLUSH_WIDTH - inIndexes.length - requestIds.length }, () => ({
      channel: FlushChannel.empty,
      inIndex: 0n,
      requestId: empty,
    })),
  ];
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

  private reader(action: VaultAction): SignetRequestResponseReader {
    return new SignetRequestResponseReader({
      requesterContractAddress: this.vaultAddress,
      requesterRequestsPath: REQUEST_MAPS[action].path,
      signetContractAddress: this.input.centralAddress,
      publicDataProvider: this.providers.publicDataProvider,
      eventSource: signetEventSourceFromIndexer({ queryUrl: this.input.config.indexerUrl }),
    });
  }

  // The user's secret is also the vault's deployer identity, which gates the
  // configuration and approval circuits; the deployer wallet only pays for the deploy.
  async deployAndInitialise(): Promise<void> {
    const { config } = this.input;
    this.targets = await this.evm.deployTargets();
    const deployerKeys = deriveAccountKeys(this.input.deployerSeed, config.networkId);
    await withSyncedWalletFacade(deployerKeys, config, async (facade) => {
      const providers = this.providersFor(facade, deployerKeys, "vault-deployer.leveldb");
      diagnostics("deploying the vault");
      this.vaultAddress = await deployVault(
        facade,
        deployerKeys,
        providers.publicDataProvider,
        config.networkId,
        this.input.centralAddress,
        this.userSecret,
      );
    });
    this.responseKey = deriveMidnightResponseKey(this.input.mpcPublicKey, this.vaultAddress);
    this.vaultEvm = deriveEvmAddress(
      this.input.mpcPublicKey,
      this.vaultAddress,
      bytesToHex(asciiPadded("vault", 32)),
    );
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
    diagnostics("initialising the vault");
    await this.vault.callTx.initialise(
      hexToBytes(this.vaultEvm),
      hexToBytes(this.targets.router),
      hexToBytes(this.targets.usdc),
      hexToBytes(this.targets.stata),
      CHAIN_ID,
      this.responseKey,
      1n,
      BigInt(await this.evm.provider.getBlockNumber()),
    );
    // initialise allows the stata underlying; the swap buys the output token.
    await this.vault.callTx.addAllowedToken(hexToBytes(this.targets.output));
    const configured = await this.readLedger();
    if (
      !configured.initialised ||
      configured.evmChainId !== CHAIN_ID ||
      !configured.allowedTokens.member(hexToBytes(this.targets.output))
    ) {
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

  // The flush's ledger work goes wholly in the fallible section: midnight-js sections a
  // call before the wallet adds its fee payment, and a guaranteed flush plus that payment
  // can exceed the node's time-to-dismiss cap. Mirrors submitFlush in the vault package.
  private async flush(inIndexes: readonly bigint[], requestIds: readonly Uint8Array[]) {
    const call = await createUnprovenCallTx(this.providers, {
      ...createCallTxOptions(
        vaultCompiledContract,
        "flushQueue",
        this.vaultAddress,
        VAULT_PRIVATE_STATE_ID,
        undefined,
        [flushSlots(inIndexes, requestIds)],
      ),
      privateStateId: VAULT_PRIVATE_STATE_ID,
    });
    const [guaranteed, fallible] = call.public.partitionedTranscript;
    const raw = await this.providers.publicDataProvider.queryContractState(this.vaultAddress);
    // The ledger's ContractCallPrototype takes only its own ContractOperation.
    const operation = raw && ContractState.deserialize(raw.serialize()).operation("flushQueue");
    if (!operation?.verifierKey) throw new Error("flushQueue has no verifier key on chain");
    const prototype = new ContractCallPrototype(
      this.vaultAddress,
      "flushQueue",
      operation,
      undefined,
      guaranteed ?? fallible,
      call.private.privateTranscriptOutputs,
      call.private.input,
      call.private.output,
      communicationCommitmentRandomness(),
      encodeContractKeyLocation({
        contractAddress: this.vaultAddress,
        circuitId: "flushQueue",
        verifierKeyHash: hashVerifierKey(operation.verifierKey),
      }),
    );
    const unprovenTx = Transaction.fromPartsRandomized(
      this.input.config.networkId,
      undefined,
      undefined,
      Intent.new(new Date(Date.now() + FLUSH_TTL_MS)).addCall(prototype),
    );
    const finalized = await submitTx(this.providers, { unprovenTx, circuitId: "flushQueue" });
    if (finalized.status !== SucceedEntirely) {
      throw new Error(`the flush finalized as ${finalized.status}`);
    }
  }

  private sendCircuit(action: VaultAction) {
    const calls = this.vault.callTx;
    switch (action) {
      case Action.approve:
        return calls.sendApprove;
      case Action.deposit:
        return calls.sendDeposit;
      case Action.withdraw:
        return calls.sendWithdraw;
      case Action.swap:
        return calls.sendSwap;
      case Action.supply:
        return calls.sendSupply;
      case Action.redeem:
        return calls.sendRedeem;
    }
  }

  // Flushes the started requests into the output buffer, then sends each, reading its
  // request id from the eviction map entry its send wrote.
  private async flushAndSend(started: readonly StartedRequest[]): Promise<SentRequest[]> {
    await this.flush(
      started.map((request) => request.inIndex),
      [],
    );
    const flushed = await this.readLedger();
    const sent: SentRequest[] = [];
    for (const request of started) {
      const outIndex = [...flushed.outputRequestBuffer].find(
        ([, { entry }]) => entry.action === request.action && entry.inIndex === request.inIndex,
      )?.[0];
      if (outIndex === undefined) throw new Error(`the flush did not move ${request.operation}`);
      await this.sendCircuit(request.action)(outIndex);
      const outHex = bytesToHex(outIndex);
      const ids = [...(await this.readLedger()).evictionMap]
        .filter(([, index]) => bytesToHex(index) === outHex)
        .map(([id]) => id);
      const [requestId] = ids;
      if (requestId === undefined || ids.length !== 1) {
        throw new Error(`${request.operation} recorded ${String(ids.length)} request ids`);
      }
      const id = requestIdHex(requestId);
      const placement = this.lastPlacement;
      const phase = placement.some((call) => call.fallibleNotifications.includes(id))
        ? "fallible"
        : placement.some((call) => call.guaranteedNotifications.includes(id))
          ? "guaranteed"
          : "missing";
      diagnostics(`${request.operation} notified ${id} in the ${phase} transcript`);
      sent.push({ ...request, requestId: id, placement });
    }
    return sent;
  }

  // Waits for every MPC signature, executes the transactions in nonce order, recomputes the
  // output the MPC attests and waits for attestations that verify against the response key.
  // Then queues each attestation and flushes them, ready for the complete circuits.
  private async executeAll(
    requests: readonly SentRequest[],
    beforeExecution?: () => Promise<void>,
  ): Promise<Map<string, AttestedRequest>> {
    const signed = await Promise.all(
      requests.map(async (request) => ({
        request,
        transaction: await poll(`${request.operation} signature`, () =>
          this.reader(request.action).getSignedEvmTransaction(request.requestId, request.signer),
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
      const returnData = await this.evm.returnData(receipt.hash);
      const decoded = deserializeEvmOutput(request.outputSchema, returnData);
      if ("success" in decoded && decoded.success !== true) {
        throw new Error(`${request.operation} returned false`);
      }
      diagnostics(`${request.operation} executed in EVM block ${receipt.blockNumber}`);
      executed.push({
        ...request,
        evmTransaction: receipt.hash,
        evmBlockHeight: receipt.blockNumber,
        decoded,
        output: executedEvmRespondOutput(request.outputSchema, true, {
          kind: EvmTraceOutputKind.Output,
          returnData,
        }),
      });
    }
    const attested = new Map<string, AttestedRequest>();
    for (const request of executed) {
      const event = await poll(`${request.operation} attestation`, () =>
        this.reader(request.action).getVerifiedRespondBidirectionalEvent(
          request.requestId,
          request.output,
          this.responseKey,
        ),
      );
      if (event.blockHeight !== BigInt(request.evmBlockHeight)) {
        throw new Error(`${request.operation} attested height ${event.blockHeight}`);
      }
      const circuitInput = respondBidirectionalEventToCircuitInput(event);
      if (request.output.length === 1) {
        await this.vault.callTx.queueAttestation1(circuitInput, request.output);
      } else if (request.output.length === 32) {
        await this.vault.callTx.queueAttestation32(circuitInput, request.output);
      } else {
        throw new Error(`no queue circuit takes ${String(request.output.length)} output bytes`);
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
    const requestIds = executed.map((request) => hexToBytes(request.requestId));
    await this.flush([], requestIds);
    const flushed = await this.readLedger();
    if (requestIds.some((id) => !flushed.outputAttestationBuffer.member(id))) {
      throw new Error("the flush left an attestation queued");
    }
    return attested;
  }

  private async removed(request: SentRequest): Promise<void> {
    const map = (await this.readLedger())[REQUEST_MAPS[request.action].field];
    if (map.member(hexToBytes(request.requestId))) {
      throw new Error(`${request.operation} still holds the settled request ${request.requestId}`);
    }
  }

  async run(): Promise<VaultRunResult> {
    const transferSchema = pureCircuits.vaultOutputSchema();
    const { usdc, output, stata } = this.targets;
    const wallet = this.input.userFacade;

    // One deposit funds every later leg; both approvals ride the same flush.
    diagnostics("queueing the deposit and approvals");
    const opening: StartedRequest[] = [
      {
        operation: "deposit",
        action: Action.deposit,
        inIndex: newInputIndex(),
        signer: this.userEvm,
        outputSchema: transferSchema,
      },
      {
        operation: "approveRouter",
        action: Action.approve,
        inIndex: newInputIndex(),
        signer: this.vaultEvm,
        outputSchema: transferSchema,
      },
      {
        operation: "approveStata",
        action: Action.approve,
        inIndex: newInputIndex(),
        signer: this.vaultEvm,
        outputSchema: transferSchema,
      },
    ];
    const [depositStart, routerStart, stataStart] = opening as [
      StartedRequest,
      StartedRequest,
      StartedRequest,
    ];
    await this.vault.callTx.startDeposit(
      depositStart.inIndex,
      BigInt(await this.evm.provider.getTransactionCount(this.userEvm)),
      DEPOSIT_GAS,
      { erc20Address: hexToBytes(usdc), amount: DEPOSIT_AMOUNT },
    );
    await this.vault.callTx.startApproveRouter(routerStart.inIndex, hexToBytes(usdc));
    await this.vault.callTx.startApproveStata(stataStart.inIndex);
    const openingSent = await this.flushAndSend(opening);
    const vaultBefore = await this.evm.balanceOf(usdc, this.vaultEvm);
    const openingSettled = await this.executeAll(openingSent);
    if ((await this.evm.balanceOf(usdc, this.vaultEvm)) - vaultBefore !== DEPOSIT_AMOUNT) {
      throw new Error("the deposit did not move the ERC20 into the vault account");
    }
    const deposit = attestedOf(openingSettled, "deposit");
    await this.vault.callTx.completeDeposit(
      hexToBytes(deposit.requestId),
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
    for (const operation of ["approveRouter", "approveStata"]) {
      const approval = attestedOf(openingSettled, operation);
      await this.vault.callTx.completeApprove(hexToBytes(approval.requestId), approval.output);
      await this.removed(approval);
    }
    await this.removed(deposit);
    await this.expectBalance(usdc, DEPOSIT_AMOUNT);

    diagnostics("queueing the withdraw, swap and supply");
    const legs: StartedRequest[] = [
      {
        operation: "withdraw",
        action: Action.withdraw,
        inIndex: newInputIndex(),
        signer: this.vaultEvm,
        outputSchema: transferSchema,
      },
      {
        operation: "swap",
        action: Action.swap,
        inIndex: newInputIndex(),
        signer: this.vaultEvm,
        outputSchema: pureCircuits.swapOutputSchema(),
      },
      {
        operation: "supply",
        action: Action.supply,
        inIndex: newInputIndex(),
        signer: this.vaultEvm,
        outputSchema: pureCircuits.supplyOutputSchema(),
      },
    ];
    const [withdrawStart, swapStart, supplyStart] = legs as [
      StartedRequest,
      StartedRequest,
      StartedRequest,
    ];
    await this.vault.callTx.startWithdraw(
      withdrawStart.inIndex,
      {
        erc20Address: hexToBytes(usdc),
        amount: WITHDRAW_AMOUNT,
        destEvmAddress: hexToBytes(this.userEvm),
      },
      this.coin(usdc, WITHDRAW_AMOUNT),
    );
    // Each surrendered coin is split from the wallet's change of the previous one.
    await wallet.waitForSyncedState();
    await this.vault.callTx.startSwap(
      swapStart.inIndex,
      {
        erc20AddressIn: hexToBytes(usdc),
        erc20AddressOut: hexToBytes(output),
        fee: SWAP_FEE,
        amountOut: SWAP_AMOUNT_OUT,
        amountInMaximum: SWAP_AMOUNT_IN_MAXIMUM,
      },
      this.coin(usdc, SWAP_AMOUNT_IN_MAXIMUM),
    );
    await wallet.waitForSyncedState();
    await this.vault.callTx.startSupply(
      supplyStart.inIndex,
      { amount: SUPPLY_AMOUNT },
      this.coin(usdc, SUPPLY_AMOUNT),
    );
    const legsSent = await this.flushAndSend(legs);
    const userBefore = await this.evm.balanceOf(usdc, this.userEvm);
    const settled = await this.executeAll(legsSent);
    const withdraw = attestedOf(settled, "withdraw");
    const swap = attestedOf(settled, "swap");
    const supply = attestedOf(settled, "supply");
    if ((await this.evm.balanceOf(usdc, this.userEvm)) - userBefore !== WITHDRAW_AMOUNT) {
      throw new Error("the withdraw did not pay the destination");
    }
    const amountIn = await this.evm.quoteSwap(this.targets.router, SWAP_AMOUNT_OUT);
    if (swap.decoded.amountIn !== amountIn) throw new Error("the swap attested another amountIn");
    const shares = supply.decoded.shares;
    if (shares !== SUPPLY_AMOUNT) throw new Error(`the supply attested ${String(shares)} shares`);
    await this.vault.callTx.completeWithdraw(
      hexToBytes(withdraw.requestId),
      withdraw.output,
      randomBytes(32),
    );
    await this.vault.callTx.completeSwap(
      hexToBytes(swap.requestId),
      swap.output,
      randomBytes(32),
      randomBytes(32),
    );
    await this.vault.callTx.completeSupply(
      hexToBytes(supply.requestId),
      supply.output,
      randomBytes(32),
    );
    await this.removed(withdraw);
    await this.removed(swap);
    await this.removed(supply);
    const usdcAfterLegs = DEPOSIT_AMOUNT - WITHDRAW_AMOUNT - amountIn - SUPPLY_AMOUNT;
    await this.expectBalance(usdc, usdcAfterLegs);
    await this.expectBalance(output, SWAP_AMOUNT_OUT);
    await this.expectBalance(stata, SUPPLY_AMOUNT);

    diagnostics("queueing the redeem");
    const redeemStart: StartedRequest = {
      operation: "redeem",
      action: Action.redeem,
      inIndex: newInputIndex(),
      signer: this.vaultEvm,
      outputSchema: pureCircuits.redeemOutputSchema(),
    };
    await this.vault.callTx.startRedeem(
      redeemStart.inIndex,
      { shares: SUPPLY_AMOUNT },
      this.coin(stata, SUPPLY_AMOUNT),
    );
    const redeemSent = await this.flushAndSend([redeemStart]);
    let assets = 0n;
    const redeem = attestedOf(
      await this.executeAll(redeemSent, async () => {
        await this.evm.mint(usdc, stata, REDEEM_YIELD);
        assets = await this.evm.previewRedeem(stata, SUPPLY_AMOUNT);
      }),
      "redeem",
    );
    if (assets <= SUPPLY_AMOUNT || redeem.decoded.assets !== assets) {
      throw new Error(`the redeem attested ${String(redeem.decoded.assets)}, expected ${assets}`);
    }
    await this.vault.callTx.completeRedeem(
      hexToBytes(redeem.requestId),
      redeem.output,
      randomBytes(32),
    );
    await this.removed(redeem);
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
