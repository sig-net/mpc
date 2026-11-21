import { randomBytes } from "node:crypto";
import { join } from "node:path";
import {
  ContractState as RuntimeContractState,
  rawTokenType,
} from "@midnight-ntwrk/compact-runtime";
import {
  createCallTxOptions,
  createUnprovenCallTx,
  findDeployedContract,
  submitCallTx,
  submitTx,
  type FoundContract,
} from "@midnight-ntwrk/midnight-js/contracts";
import {
  encodeContractKeyLocation,
  hashVerifierKey,
  LedgerTransaction,
  SucceedEntirely,
  type UnprovenTx,
} from "@midnight-ntwrk/midnight-js/types";
import {
  communicationCommitmentRandomness,
  ContractCallPrototype,
  ContractState,
  Intent,
  Transaction,
  type UnprovenTransaction,
} from "@midnightntwrk/ledger-v9";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import {
  deriveAccountKeys,
  withSyncedWalletFacade,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import {
  asciiPadded,
  assembleCalldata,
  broadcastTronTransaction,
  bytesToHex,
  deriveEvmAddress,
  deriveMidnightResponseKey,
  deserializeEvmOutput,
  EvmTraceOutputKind,
  evmTraceOutputFromTronReceipt,
  executedEvmRespondOutput,
  getSolidifiedTronReferenceBlock,
  hexToBytes,
  isEvmContractCall,
  OutputKind,
  requestIdHex,
  respondBidirectionalEventToCircuitInput,
  signBidirectionalEventToUnsignedTronTransaction,
  signetEventSourceFromIndexer,
  SignetRequestResponseReader,
  tronAddressFromEvm,
  TronBroadcastOutcome,
  TronExecutionResult,
  tronReceiptExecutionResult,
  type RequestIdHex,
  type RespondBidirectionalEvent,
  type Secp256k1Point,
} from "@sig-net/midnight";
import { JsonRpcProvider, recoverAddress, Signature } from "ethers";
import {
  Action,
  FlushChannel,
  ledger,
  pureCircuits,
  type FlushSlot,
  type GasParams,
  type TokenFees,
} from "./managed/erc20-vault/contract/index.js";
import { placementOf, type CallPlacement } from "./placement.js";
import {
  buildVaultProviders,
  VAULT_PRIVATE_STATE_ID,
  vaultCompiledContract,
  type VaultContract,
  type VaultProviders,
} from "./vault-contract.js";
import { deployVault } from "./vault-deploy.js";
import { VaultEvm, type VaultTargets } from "./vault-evm.js";
import { TronChain } from "./vault-tron.js";

type VaultHandle = FoundContract<VaultContract>;
type VaultLedger = ReturnType<typeof ledger>;

/** Each action's request map: its ledger field and compiled ledger path. */
const REQUEST_MAPS = {
  [Action.approve]: { field: "bidirectionalApproveMap", path: [1, 13] },
  [Action.deposit]: { field: "bidirectionalDepositMap", path: [2, 0] },
  [Action.tronDeposit]: { field: "bidirectionalTronDepositMap", path: [2, 2] },
  [Action.withdraw]: { field: "bidirectionalWithdrawMap", path: [2, 4] },
  [Action.swap]: { field: "bidirectionalSwapMap", path: [2, 6] },
  [Action.supply]: { field: "bidirectionalSupplyMap", path: [2, 8] },
  [Action.redeem]: { field: "bidirectionalRedeemMap", path: [2, 10] },
  [Action.tronWithdraw]: { field: "bidirectionalTronWithdrawMap", path: [2, 13] },
} as const;
type VaultAction = keyof typeof REQUEST_MAPS;

const FLUSH_WIDTH = 10;
const FLUSH_TTL_MS = 5 * 60_000;
// A stale flush waits for the real flush and the send it rides with to be proven.
const STALE_FLUSH_TTL_MS = 30 * 60_000;
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
const NO_FEES: TokenFees = { withdraw: 0n, swap: 0n, supply: 0n, redeem: 0n };
// The Tron run: an ETH deposit and withdraw beside a Tron deposit and withdraw.
const TRON_DEPOSIT_AMOUNT = 300_000n;
const TRON_WITHDRAW_AMOUNT = 100_000n;
const TRON_WITHDRAW_FEE = 1_000n;
// What the user's Tron account burns for its deposit transfer, and the vault's for its
// withdrawals: TRE prices energy, so both accounts hold TRX.
const TRON_DEPOSIT_FEE_LIMIT = 100_000_000n;
const TRON_ACCOUNT_TRX = 2_000_000_000n;
const TRON_WINDOW_MS = 3_600_000n;
// Two minutes above the start's 600 s minimum, which the block including the start must
// still clear after proving; the unsent withdraw's refund opens about eleven minutes after
// its start, mostly while the other withdraws run.
const TRON_UNSENT_WINDOW_MS = 720_000n;

export interface VaultRunInput {
  config: MidnightNodeConfig;
  artifactDir: string;
  centralAddress: string;
  responderAddress: string;
  mpcPublicKey: string;
  evmRpcUrl: string;
  evmFunderKey: string;
  deployerSeed: string;
  userSeed: string;
  userFacade: WalletFacade;
  /** The TRE chain of a Tron run; the ETH-only runs initialise without one. */
  tron?: VaultTronInput;
}

export interface VaultTronInput {
  rpcUrl: string;
  funderKey: string;
  /** The TRC-20 artifact the run deploys: `name`, `abi` and creation `bytecode`. */
  tokenArtifact: string;
}

/** The chain a request's transaction executes on. */
enum TargetChain {
  Ethereum = "ethereum",
  Tron = "tron",
}

export interface VaultOperation {
  operation: string;
  chain: TargetChain;
  requestId: string;
  /** Placement of the transaction whose singleton call notified the request. */
  placement: CallPlacement[];
  /** The executed transaction's hash (EVM) or id (Tron), hex. */
  transaction: string;
  /** The block height the attestation commits to. */
  blockHeight: number;
  /** Serialized output the attestation signs, hex. */
  output: string;
  /** From the notifying send's finalisation to the MPC signature's first read. */
  sendToSignatureMs: number;
  /** From the transaction's broadcast to the verified attestation's first read. */
  broadcastToAttestationMs: number;
}

/** The vault's two last-seen heights at one point of the run. */
interface LastSeen {
  ethereum: number;
  tron: number;
}

/** The outcome of {@link runVaultPartialSend}. */
export interface VaultPartialSendResult {
  vaultAddress: string;
  requestId: string;
  status: string;
  /** The indexer's per-segment results, `transactionResult.segments`. */
  segments: [number, string][];
  blockHeight: number;
  txHash: string;
  placement: CallPlacement[];
  /** Whether the vault's deposit map holds the request after the transaction. */
  committed: boolean;
  /** Whether a second send of the same entry fails with "Request already sent". */
  retryRejected: boolean;
  retryError?: string;
}

export interface VaultRunResult {
  vaultAddress: string;
  targets: VaultTargets;
  operations: VaultOperation[];
}

/** The outcome of {@link runVaultTron}. */
export interface VaultTronRunResult {
  vaultAddress: string;
  /** The deployed TRC-20, 21-byte hex. */
  tronToken: string;
  operations: VaultOperation[];
  /**
   * The last-seen heights before the withdraw attestations, after the ETH one alone is
   * flushed, and after the Tron one is flushed too.
   */
  lastSeen: { before: LastSeen; afterEthereum: LastSeen; afterTron: LastSeen };
  /** The refusals of each chain's attestation presented to the other chain's complete. */
  crossChainRefusals: { tronCompleteOfEthereum: string; ethereumCompleteOfTron: string };
  /** The withdraw recipient's TRC-20 balance around the withdraw. */
  recipient: { address: string; before: number; after: number };
  /**
   * A Tron withdraw left unsent until its window closed to sends: the late send's refusal,
   * and the refund that re-minted its amount.
   */
  unsentRefund: { lateSendRefusal: string; waitedMs: number };
}

/** A request its start circuit queued under `inIndex`. */
interface StartedRequest {
  operation: string;
  action: VaultAction;
  inIndex: bigint;
  /** The account the MPC signs the request's transaction with: EVM hex, or Tron 21-byte hex. */
  signer: string;
  outputSchema: Uint8Array;
}

interface SentRequest extends StartedRequest {
  requestId: RequestIdHex;
  placement: CallPlacement[];
  /** When the send that notified the request finalised. */
  sentAt: number;
}

/** A request whose transaction executed, with the output the MPC must attest. */
interface ExecutedRequest extends SentRequest {
  transaction: string;
  blockHeight: number;
  decoded: Record<string, unknown>;
  output: Uint8Array;
  signedAt: number;
  broadcastAt: number;
}

interface AttestedRequest extends ExecutedRequest {
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
  private readonly tron: TronChain | undefined;

  constructor(private readonly input: VaultRunInput) {
    this.evm = new VaultEvm(
      new JsonRpcProvider(input.evmRpcUrl, undefined, { cacheTimeout: -1 }),
      input.evmFunderKey,
    );
    this.userSecret = hexToBytes(input.userSeed);
    this.tron = input.tron && new TronChain(input.tron.rpcUrl, input.tron.funderKey);
  }

  private tronChain(): TronChain {
    if (this.tron === undefined) throw new Error("this run has no Tron chain");
    return this.tron;
  }

  private async readLedger(): Promise<VaultLedger> {
    const state = await this.providers.publicDataProvider.queryContractState(this.vaultAddress);
    if (!state) throw new Error(`no vault state at ${this.vaultAddress}`);
    return ledger(state.contractState.deserialize({ v9: RuntimeContractState }).data);
  }

  // An ERC20's vault coin colour, or a TRC-20's (`token` then 21-byte hex) on the Tron chain.
  private tokenType(token: string, chain = TargetChain.Ethereum): string {
    return rawTokenType(
      chain === TargetChain.Tron
        ? pureCircuits.vaultTronTokenDomainSeparator(hexToBytes(token).subarray(1))
        : pureCircuits.vaultTokenDomainSeparator(hexToBytes(token)),
      this.vaultAddress,
    );
  }

  private coin(token: string, value: bigint, chain = TargetChain.Ethereum) {
    return { nonce: randomBytes(32), color: hexToBytes(this.tokenType(token, chain)), value };
  }

  private async shieldedBalance(token: string, chain: TargetChain): Promise<bigint> {
    const state = await this.input.userFacade.waitForSyncedState();
    return state.shielded.balances[this.tokenType(token, chain)] ?? 0n;
  }

  // Minted coins reach the wallet once it syncs the settling block.
  private async expectBalance(
    token: string,
    expected: bigint,
    chain = TargetChain.Ethereum,
  ): Promise<void> {
    await poll(`shielded balance ${expected} of ${token}`, async () =>
      (await this.shieldedBalance(token, chain)) === expected ? true : undefined,
    );
  }

  private reader(action: VaultAction): SignetRequestResponseReader {
    return new SignetRequestResponseReader({
      requesterContractAddress: this.vaultAddress,
      requesterRequestsPath: REQUEST_MAPS[action].path,
      responderContractAddress: this.input.responderAddress,
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
    // Fees are taken on Tron withdrawals only; their fee coins go to the deployer wallet.
    const feeRecipient = deployerKeys.shieldedSecretKeys;
    await this.vault.callTx.initialise(
      hexToBytes(this.vaultEvm),
      hexToBytes(this.targets.router),
      hexToBytes(this.targets.usdc),
      hexToBytes(this.targets.stata),
      CHAIN_ID,
      this.responseKey,
      1n,
      BigInt(await this.evm.provider.getBlockNumber()),
      (await this.tron?.solidifiedHeight()) ?? 0n,
      // No TRC-20 of the run reports success as false.
      new Uint8Array(20),
      NO_FEES,
      NO_FEES,
      { bytes: hexToBytes(feeRecipient.coinPublicKey) },
      hexToBytes(feeRecipient.encryptionPublicKey),
    );
    // initialise allows the stata underlying; the swap buys the output token.
    await this.vault.callTx.addAllowedToken(hexToBytes(this.targets.output), NO_FEES);
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
    const unprovenTx = await this.buildFlush(inIndexes, requestIds, FLUSH_TTL_MS);
    const finalized = await submitTx(this.providers, {
      unprovenTx: LedgerTransaction.seal("v9", "Unproven", unprovenTx),
      circuitId: "flushQueue",
    });
    if (finalized.status !== SucceedEntirely) {
      throw new Error(`the flush finalized as ${finalized.status}`);
    }
  }

  private async buildFlush(
    inIndexes: readonly bigint[],
    requestIds: readonly Uint8Array[],
    ttlMs: number,
  ): Promise<UnprovenTransaction> {
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
    const operation = raw?.contractState.deserialize({ v9: ContractState }).operation("flushQueue");
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
    return Transaction.fromPartsRandomized(
      this.input.config.networkId,
      undefined,
      undefined,
      Intent.new(new Date(Date.now() + ttlMs)).addCall(prototype),
    );
  }

  private sendCircuit(action: VaultAction) {
    const calls = this.vault.callTx;
    switch (action) {
      case Action.approve:
        return calls.sendApprove;
      case Action.deposit:
        return calls.sendDeposit;
      case Action.tronDeposit:
        return calls.sendTronDeposit;
      case Action.withdraw:
        return calls.sendWithdraw;
      case Action.swap:
        return calls.sendSwap;
      case Action.supply:
        return calls.sendSupply;
      case Action.redeem:
        return calls.sendRedeem;
      case Action.tronWithdraw:
        return calls.sendTronWithdraw;
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
      const sentAt = Date.now();
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
      sent.push({ ...request, requestId: id, placement, sentAt });
    }
    return sent;
  }

  // Waits for every MPC signature and executes the transactions in nonce order on the EVM.
  private async executeEvm(
    requests: readonly SentRequest[],
    beforeExecution?: () => Promise<void>,
  ): Promise<ExecutedRequest[]> {
    const signed = await Promise.all(
      requests.map(async (request) => {
        const transaction = await poll(`${request.operation} signature`, () =>
          this.reader(request.action).getSignedEvmTransaction(request.requestId, request.signer),
        );
        return { request, transaction, signedAt: Date.now() };
      }),
    );
    await beforeExecution?.();
    signed.sort((a, b) =>
      a.request.signer === b.request.signer
        ? a.transaction.nonce - b.transaction.nonce
        : a.request.signer.localeCompare(b.request.signer),
    );
    const executed: ExecutedRequest[] = [];
    for (const { request, transaction, signedAt } of signed) {
      const broadcastAt = Date.now();
      const receipt = await this.evm.execute(transaction);
      const returnData = await this.evm.returnData(receipt.hash);
      const decoded = deserializeEvmOutput(request.outputSchema, returnData);
      if ("success" in decoded && decoded.success !== true) {
        throw new Error(`${request.operation} returned false`);
      }
      diagnostics(`${request.operation} executed in EVM block ${receipt.blockNumber}`);
      executed.push({
        ...request,
        transaction: receipt.hash,
        blockHeight: receipt.blockNumber,
        decoded,
        output: executedEvmRespondOutput(request.outputSchema, true, {
          kind: EvmTraceOutputKind.Output,
          returnData,
        }),
        signedAt,
        broadcastAt,
      });
    }
    return executed;
  }

  // Waits for the MPC signature of a Tron request, checks it recovers to the request's
  // derived owner, broadcasts the transaction and rebuilds the output the MPC attests from
  // its solidified receipt.
  private async executeTron(request: SentRequest): Promise<ExecutedRequest> {
    const tron = this.tronChain();
    const reader = this.reader(request.action);
    const record = await reader.getTronSignatureRequest(request.requestId);
    const unsigned = signBidirectionalEventToUnsignedTronTransaction(
      record,
      this.input.mpcPublicKey,
    );
    if (bytesToHex(unsigned.owner.bytes) !== request.signer) {
      throw new Error(`${request.operation} is owned by ${unsigned.owner.base58}`);
    }
    const signedTransaction = await poll(`${request.operation} signature`, () =>
      reader.getSignedTronTransaction(request.requestId, this.input.mpcPublicKey),
    );
    const signedAt = Date.now();
    // The signed protobuf ends with the one 65-byte [r || s || v] signature.
    const signature = signedTransaction.subarray(signedTransaction.length - 65);
    const v = signature.at(64);
    if (v === undefined) throw new Error(`${request.operation}'s signed transaction is too short`);
    const recovered = recoverAddress(
      unsigned.txId,
      Signature.from({
        r: `0x${bytesToHex(signature.subarray(0, 32))}`,
        s: `0x${bytesToHex(signature.subarray(32, 64))}`,
        yParity: (v >= 27 ? v - 27 : v) === 0 ? 0 : 1,
      }),
    );
    if (bytesToHex(tronAddressFromEvm(recovered)) !== request.signer) {
      throw new Error(`${request.operation}'s signature recovers to ${recovered}`);
    }
    const broadcastAt = Date.now();
    const outcome = await broadcastTronTransaction(tron.rpcUrl, signedTransaction);
    diagnostics(
      `${request.operation} broadcast ${bytesToHex(unsigned.txId)}: ${TronBroadcastOutcome[outcome]}`,
    );
    const receipt = await tron.receipt(unsigned.txId);
    if (tronReceiptExecutionResult(receipt) !== TronExecutionResult.Succeeded) {
      throw new Error(`${request.operation} ran ${String(receipt.receiptResult)}`);
    }
    const output = executedEvmRespondOutput(
      record.outputDeserializationSchema,
      isEvmContractCall(assembleCalldata(record.txParams.calldata)),
      evmTraceOutputFromTronReceipt(receipt.body),
    );
    const decoded = deserializeEvmOutput(
      request.outputSchema,
      receipt.contractResult.at(0) ?? new Uint8Array(),
    );
    if (decoded.success !== true) throw new Error(`${request.operation} returned false`);
    diagnostics(`${request.operation} executed in Tron block ${receipt.blockNumber}`);
    return {
      ...request,
      transaction: bytesToHex(unsigned.txId),
      blockHeight: Number(receipt.blockNumber),
      decoded,
      output,
      signedAt,
      broadcastAt,
    };
  }

  // Waits for an attestation that verifies against the response key at the executed height.
  private async attest(request: ExecutedRequest): Promise<AttestedRequest> {
    const event = await poll(`${request.operation} attestation`, () =>
      this.reader(request.action).getVerifiedRespondBidirectionalEvent(
        request.requestId,
        request.output,
        this.responseKey,
      ),
    );
    const attestedAt = Date.now();
    if (event.outputKind !== OutputKind.executed) {
      throw new Error(`${request.operation} attested ${OutputKind[event.outputKind]}`);
    }
    if (event.blockHeight !== BigInt(request.blockHeight)) {
      throw new Error(`${request.operation} attested height ${event.blockHeight}`);
    }
    this.operations.push({
      operation: request.operation,
      chain:
        request.action === Action.tronDeposit || request.action === Action.tronWithdraw
          ? TargetChain.Tron
          : TargetChain.Ethereum,
      requestId: request.requestId,
      placement: request.placement,
      transaction: request.transaction,
      blockHeight: request.blockHeight,
      output: bytesToHex(request.output),
      sendToSignatureMs: request.signedAt - request.sentAt,
      broadcastToAttestationMs: attestedAt - request.broadcastAt,
    });
    return { ...request, event };
  }

  // Queues each attestation, then flushes them in one flush, ready for the complete circuits.
  private async queueAndFlush(attested: readonly AttestedRequest[]): Promise<void> {
    for (const request of attested) {
      await this.vault.callTx.queueAttestation(
        respondBidirectionalEventToCircuitInput(request.event),
      );
    }
    const requestIds = attested.map((request) => hexToBytes(request.requestId));
    await this.flush([], requestIds);
    const flushed = await this.readLedger();
    if (requestIds.some((id) => !flushed.outputAttestationBuffer.member(id))) {
      throw new Error("the flush left an attestation queued");
    }
  }

  // Executes every request on the EVM, waits for the attestations that verify against the
  // response key, then queues and flushes them.
  private async executeAll(
    requests: readonly SentRequest[],
    beforeExecution?: () => Promise<void>,
  ): Promise<Map<string, AttestedRequest>> {
    const attested: AttestedRequest[] = [];
    for (const request of await this.executeEvm(requests, beforeExecution)) {
      attested.push(await this.attest(request));
    }
    await this.queueAndFlush(attested);
    return new Map(attested.map((request) => [request.operation, request]));
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

  /**
   * CertiK SNA-07's shape on the real vault: the user's own wallet sends their flushed deposit
   * in one intent, beside a flush proven before the deposit was flushed, which fails when
   * applied. `sendDeposit` lets anyone send a flushed entry, and the reader's check does not
   * depend on the sender.
   * The send commits, so the transaction partially succeeds, and a second send of the same
   * entry is refused.
   */
  async partialSend(): Promise<VaultPartialSendResult> {
    const inIndex = newInputIndex();
    await this.vault.callTx.startDeposit(
      inIndex,
      BigInt(await this.evm.provider.getTransactionCount(this.userEvm)),
      DEPOSIT_GAS,
      { erc20Address: hexToBytes(this.targets.usdc), amount: DEPOSIT_AMOUNT },
    );
    const stale = await this.buildFlush([inIndex], [], STALE_FLUSH_TTL_MS);
    await this.flush([inIndex], []);
    const flushed = await this.readLedger();
    const outIndex = [...flushed.outputRequestBuffer].find(
      ([, { entry }]) => entry.action === Action.deposit && entry.inIndex === inIndex,
    )?.[0];
    if (outIndex === undefined) throw new Error("the flush did not move the deposit");
    const staleSegments = [...(stale.intents?.keys() ?? [])];
    let send: UnprovenTransaction | undefined;
    for (let attempt = 0; attempt < 32 && send === undefined; attempt += 1) {
      const built = await createUnprovenCallTx(this.providers, {
        compiledContract: vaultCompiledContract,
        contractAddress: this.vaultAddress,
        circuitId: "sendDeposit",
        privateStateId: VAULT_PRIVATE_STATE_ID,
        args: [outIndex],
      } as never);
      const tx = (built as { private: { unprovenTx: UnprovenTx } }).private.unprovenTx.deserialize({
        v9: Transaction,
      });
      if ([...(tx.intents?.keys() ?? [])].every((segment) => !staleSegments.includes(segment))) {
        send = tx;
      }
    }
    if (send === undefined) throw new Error("could not keep the send and stale flush apart");
    const tx = send.merge(stale);
    const placement = placementOf(tx);
    const proven = await this.providers.proofProvider.proveTx(
      LedgerTransaction.seal("v9", "Unproven", tx),
    );
    const balanced = await this.providers.walletProvider.balanceTx(proven);
    const txId = await this.providers.midnightProvider.submitTx(balanced);
    const finalized = await this.providers.publicDataProvider.watchForTxData(txId);
    const after = await this.readLedger();
    const outHex = bytesToHex(outIndex);
    const ids = [...after.evictionMap]
      .filter(([, index]) => bytesToHex(index) === outHex)
      .map(([id]) => id);
    const [requestId] = ids;
    if (requestId === undefined || ids.length !== 1) {
      throw new Error(`the send recorded ${String(ids.length)} request ids`);
    }
    let retryError: string | undefined;
    try {
      await this.vault.callTx.sendDeposit(outIndex);
    } catch (error) {
      retryError = error instanceof Error ? error.message : String(error);
    }
    return {
      vaultAddress: this.vaultAddress,
      requestId: requestIdHex(requestId),
      status: String(finalized.status),
      segments: [...(finalized.segmentStatusMap ?? new Map())].map(
        ([segment, status]) => [segment, String(status)] as [number, string],
      ),
      blockHeight: finalized.blockHeight,
      txHash: String(finalized.txHash),
      placement,
      committed: after.bidirectionalDepositMap.member(requestId),
      retryRejected: retryError?.includes("Request already sent") ?? false,
      retryError,
    };
  }

  // The ETH request beside the Tron one: the EVM signs and the attestation verifies.
  private async attestEvm(request: SentRequest): Promise<AttestedRequest> {
    const [executed] = await this.executeEvm([request]);
    if (executed === undefined) throw new Error(`${request.operation} did not execute`);
    return this.attest(executed);
  }

  // Starts a Tron withdraw of TRON_WITHDRAW_AMOUNT of `token` to `recipient` (21-byte) under
  // a fresh window `windowMs` long, and returns that window.
  private async startTronWithdraw(
    inIndex: bigint,
    token: Uint8Array,
    recipient: Uint8Array,
    windowMs: bigint,
  ): Promise<Awaited<ReturnType<VaultRun["tronWindow"]>>> {
    await this.input.userFacade.waitForSyncedState();
    const configured = await this.readLedger();
    const window = await this.tronWindow(windowMs);
    // The fee coin goes to the fee recipient, so its output needs that recipient's key.
    await submitCallTx(this.providers, {
      ...createCallTxOptions(
        vaultCompiledContract,
        "startTronWithdraw",
        this.vaultAddress,
        VAULT_PRIVATE_STATE_ID,
        new Map([
          [
            bytesToHex(configured.feeRecipientCoinPublicKey.bytes),
            bytesToHex(configured.feeRecipientEncryptionPublicKey),
          ],
        ]),
        [
          inIndex,
          {
            tokenAddress: token.subarray(1),
            amount: TRON_WITHDRAW_AMOUNT,
            destTronAddress: recipient.subarray(1),
          },
          window,
          this.coin(bytesToHex(token), TRON_WITHDRAW_AMOUNT + TRON_WITHDRAW_FEE, TargetChain.Tron),
        ],
      ),
      privateStateId: VAULT_PRIVATE_STATE_ID,
    });
    return window;
  }

  private async tronWindow(windowMs = TRON_WINDOW_MS): Promise<{
    refBlockBytes: Uint8Array;
    refBlockHash: Uint8Array;
    timestamp: bigint;
    expiration: bigint;
  }> {
    // The solidified head cannot be reorganised away, so its TaPoS reference stays valid.
    const reference = await getSolidifiedTronReferenceBlock(this.tronChain().rpcUrl);
    const timestamp = BigInt(Date.now());
    return {
      refBlockBytes: reference.refBlockBytes,
      refBlockHash: reference.refBlockHash,
      timestamp,
      expiration: timestamp + windowMs,
    };
  }

  private async lastSeen(): Promise<LastSeen> {
    const state = await this.readLedger();
    return { ethereum: Number(state.globalLastSeen), tron: Number(state.tronLastSeen) };
  }

  /**
   * An ETH deposit and a Tron deposit fund a vault coin of each colour. Then an ETH withdraw
   * and a Tron withdraw run side by side: each attestation is queued and flushed while the
   * other request is still open, and each is offered to the other chain's complete circuit
   * before the real completes.
   */
  async runTron(): Promise<VaultTronRunResult> {
    const tron = this.tronChain();
    const artifact = this.input.tron?.tokenArtifact;
    if (artifact === undefined) throw new Error("this run has no Tron token artifact");
    const transferSchema = pureCircuits.vaultOutputSchema();
    const { usdc } = this.targets;

    diagnostics("deploying and allowing the TRC-20, funding the Tron accounts");
    const token = await tron.deploy(artifact);
    const tokenHex = bytesToHex(token);
    await this.vault.callTx.addAllowedTronToken(token.subarray(1), {
      ...NO_FEES,
      withdraw: TRON_WITHDRAW_FEE,
    });
    const userTron = tronAddressFromEvm(this.userEvm);
    const vaultTron = tronAddressFromEvm(this.vaultEvm);
    await tron.sendTrx(userTron, TRON_ACCOUNT_TRX);
    await tron.sendTrx(vaultTron, TRON_ACCOUNT_TRX);
    await tron.sendToken(token, userTron, TRON_DEPOSIT_AMOUNT);

    diagnostics("queueing the ETH and Tron deposits");
    const depositStart: StartedRequest = {
      operation: "deposit",
      action: Action.deposit,
      inIndex: newInputIndex(),
      signer: this.userEvm,
      outputSchema: transferSchema,
    };
    const tronDepositStart: StartedRequest = {
      operation: "tronDeposit",
      action: Action.tronDeposit,
      inIndex: newInputIndex(),
      signer: bytesToHex(userTron),
      outputSchema: transferSchema,
    };
    await this.vault.callTx.startDeposit(
      depositStart.inIndex,
      BigInt(await this.evm.provider.getTransactionCount(this.userEvm)),
      DEPOSIT_GAS,
      { erc20Address: hexToBytes(usdc), amount: WITHDRAW_AMOUNT },
    );
    await this.vault.callTx.startTronDeposit(
      tronDepositStart.inIndex,
      { ...(await this.tronWindow()), feeLimit: TRON_DEPOSIT_FEE_LIMIT },
      { tokenAddress: token.subarray(1), amount: TRON_DEPOSIT_AMOUNT },
    );
    const [depositSent, tronDepositSent] = await this.flushAndSend([
      depositStart,
      tronDepositStart,
    ]);
    if (depositSent === undefined || tronDepositSent === undefined) {
      throw new Error("the deposits were not sent");
    }
    const vaultUsdcBefore = await this.evm.balanceOf(usdc, this.vaultEvm);
    const vaultTokenBefore = await tron.balanceOf(token, vaultTron);
    const [deposit, tronDeposit] = await Promise.all([
      this.attestEvm(depositSent),
      tron.withBlocks(async () => this.attest(await this.executeTron(tronDepositSent))),
    ]);
    if ((await this.evm.balanceOf(usdc, this.vaultEvm)) - vaultUsdcBefore !== WITHDRAW_AMOUNT) {
      throw new Error("the ETH deposit did not move the ERC20 into the vault account");
    }
    if ((await tron.balanceOf(token, vaultTron)) - vaultTokenBefore !== TRON_DEPOSIT_AMOUNT) {
      throw new Error("the Tron deposit did not move the TRC-20 into the vault's Tron account");
    }
    await this.queueAndFlush([deposit, tronDeposit]);
    const noRecipient = {
      is_some: false,
      value: {
        is_left: true,
        left: { bytes: new Uint8Array(32) },
        right: { bytes: new Uint8Array(32) },
      },
    };
    await this.vault.callTx.completeDeposit(
      hexToBytes(deposit.requestId),
      deposit.output,
      randomBytes(32),
      noRecipient,
    );
    await this.vault.callTx.completeTronDeposit(
      hexToBytes(tronDeposit.requestId),
      tronDeposit.output,
      randomBytes(32),
      noRecipient,
    );
    await this.removed(deposit);
    await this.removed(tronDeposit);
    await this.expectBalance(usdc, WITHDRAW_AMOUNT);
    await this.expectBalance(tokenHex, TRON_DEPOSIT_AMOUNT, TargetChain.Tron);

    // Queued and flushed now, never sent: its refund opens while the other withdraws run.
    diagnostics("queueing and flushing a Tron withdraw nobody will send in time");
    const unsentInIndex = newInputIndex();
    const unsentWindow = await this.startTronWithdraw(
      unsentInIndex,
      token,
      tronAddressFromEvm(randomBytes(20)),
      TRON_UNSENT_WINDOW_MS,
    );
    const unsentStartedAt = Date.now();
    await this.flush([unsentInIndex], []);
    const unsentOutIndex = [...(await this.readLedger()).outputRequestBuffer].find(
      ([, { entry }]) => entry.action === Action.tronWithdraw && entry.inIndex === unsentInIndex,
    )?.[0];
    if (unsentOutIndex === undefined) throw new Error("the flush did not move the unsent withdraw");

    diagnostics("queueing the ETH and Tron withdraws");
    const recipient = tronAddressFromEvm(randomBytes(20));
    const recipientBefore = await tron.balanceOf(token, recipient);
    const withdrawStart: StartedRequest = {
      operation: "withdraw",
      action: Action.withdraw,
      inIndex: newInputIndex(),
      signer: this.vaultEvm,
      outputSchema: transferSchema,
    };
    const tronWithdrawStart: StartedRequest = {
      operation: "tronWithdraw",
      action: Action.tronWithdraw,
      inIndex: newInputIndex(),
      signer: bytesToHex(vaultTron),
      outputSchema: transferSchema,
    };
    await this.vault.callTx.startWithdraw(
      withdrawStart.inIndex,
      {
        erc20Address: hexToBytes(usdc),
        amount: WITHDRAW_AMOUNT,
        destEvmAddress: hexToBytes(this.userEvm),
      },
      this.coin(usdc, WITHDRAW_AMOUNT),
    );
    await this.startTronWithdraw(tronWithdrawStart.inIndex, token, recipient, TRON_WINDOW_MS);
    const [withdrawSent, tronWithdrawSent] = await this.flushAndSend([
      withdrawStart,
      tronWithdrawStart,
    ]);
    if (withdrawSent === undefined || tronWithdrawSent === undefined) {
      throw new Error("the withdraws were not sent");
    }
    const userUsdcBefore = await this.evm.balanceOf(usdc, this.userEvm);
    const vaultTokenBeforeWithdraw = await tron.balanceOf(token, vaultTron);
    const [withdraw, tronWithdraw] = await Promise.all([
      this.attestEvm(withdrawSent),
      tron.withBlocks(async () => this.attest(await this.executeTron(tronWithdrawSent))),
    ]);
    if ((await this.evm.balanceOf(usdc, this.userEvm)) - userUsdcBefore !== WITHDRAW_AMOUNT) {
      throw new Error("the ETH withdraw did not pay the destination");
    }
    const recipientAfter = await tron.balanceOf(token, recipient);
    if (recipientAfter - recipientBefore !== TRON_WITHDRAW_AMOUNT) {
      throw new Error(`the Tron withdraw paid ${recipientAfter - recipientBefore}`);
    }
    if (
      vaultTokenBeforeWithdraw - (await tron.balanceOf(token, vaultTron)) !==
      TRON_WITHDRAW_AMOUNT
    ) {
      throw new Error("the Tron withdraw did not leave the vault's Tron account");
    }

    // Each chain's attestation folds only into its own last-seen height.
    const before = await this.lastSeen();
    if (tronWithdraw.blockHeight <= before.tron) {
      throw new Error(
        `the Tron withdraw attested ${tronWithdraw.blockHeight}, not above ${before.tron}`,
      );
    }
    await this.queueAndFlush([withdraw]);
    const afterEthereum = await this.lastSeen();
    if (
      afterEthereum.ethereum !== Math.max(before.ethereum, withdraw.blockHeight) ||
      afterEthereum.tron !== before.tron ||
      !(await this.readLedger()).bidirectionalTronWithdrawMap.member(
        hexToBytes(tronWithdraw.requestId),
      )
    ) {
      throw new Error(`the ETH flush moved ${JSON.stringify({ before, afterEthereum })}`);
    }
    await this.queueAndFlush([tronWithdraw]);
    const afterTron = await this.lastSeen();
    if (
      afterTron.tron !== Math.max(before.tron, tronWithdraw.blockHeight) ||
      afterTron.ethereum !== afterEthereum.ethereum ||
      !(await this.readLedger()).bidirectionalWithdrawMap.member(hexToBytes(withdraw.requestId))
    ) {
      throw new Error(`the Tron flush moved ${JSON.stringify({ afterEthereum, afterTron })}`);
    }

    diagnostics("offering each chain's attestation to the other chain's complete");
    const tronCompleteOfEthereum = await refusal(() =>
      this.vault.callTx.completeTronWithdraw(
        hexToBytes(withdraw.requestId),
        withdraw.output,
        randomBytes(32),
      ),
    );
    const ethereumCompleteOfTron = await refusal(() =>
      this.vault.callTx.completeWithdraw(
        hexToBytes(tronWithdraw.requestId),
        tronWithdraw.output,
        randomBytes(32),
      ),
    );
    diagnostics(`refused: ${tronCompleteOfEthereum} / ${ethereumCompleteOfTron}`);

    await this.vault.callTx.completeWithdraw(
      hexToBytes(withdraw.requestId),
      withdraw.output,
      randomBytes(32),
    );
    await this.vault.callTx.completeTronWithdraw(
      hexToBytes(tronWithdraw.requestId),
      tronWithdraw.output,
      randomBytes(32),
    );
    await this.removed(withdraw);
    await this.removed(tronWithdraw);
    // The burns stand: no refund coin is minted back. The unsent withdraw's coin is burned.
    await this.expectBalance(usdc, 0n);
    await this.expectBalance(
      tokenHex,
      TRON_DEPOSIT_AMOUNT - 2n * (TRON_WITHDRAW_AMOUNT + TRON_WITHDRAW_FEE),
      TargetChain.Tron,
    );

    // From the expiration's whole seconds minus the send margin, the send is refused and
    // the withdrawer's refund re-mints the amount; the fee stays taken.
    const refundOpensAt =
      Number(unsentWindow.expiration / 1000n - pureCircuits.tronWithdrawSendMinRemainingSeconds()) *
      1000;
    diagnostics(`waiting for the unsent withdraw's refund to open at ${refundOpensAt}`);
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, refundOpensAt - Date.now())));
    const lateSendRefusal = await refusal(() => this.vault.callTx.sendTronWithdraw(unsentOutIndex));
    if (!lateSendRefusal.includes("too close")) {
      throw new Error(`the late send failed otherwise: ${lateSendRefusal}`);
    }
    await this.vault.callTx.refundUnsentTronWithdraw(unsentInIndex, randomBytes(32));
    const waitedMs = Date.now() - unsentStartedAt;
    await this.expectBalance(
      tokenHex,
      TRON_DEPOSIT_AMOUNT - TRON_WITHDRAW_AMOUNT - 2n * TRON_WITHDRAW_FEE,
      TargetChain.Tron,
    );
    const settled = await this.readLedger();
    const leftovers = Object.entries({
      inputRequestBuffer: settled.inputRequestBuffer.size(),
      outputRequestBuffer: settled.outputRequestBuffer.size(),
      inputAttestationBuffer: settled.inputAttestationBuffer.size(),
      outputAttestationBuffer: settled.outputAttestationBuffer.size(),
      evictionMap: settled.evictionMap.size(),
      depositArgsMap: settled.depositArgsMap.size(),
      tronDepositArgsMap: settled.tronDepositArgsMap.size(),
      withdrawArgsMap: settled.withdrawArgsMap.size(),
      tronWithdrawArgsMap: settled.tronWithdrawArgsMap.size(),
      ...Object.fromEntries(
        Object.values(REQUEST_MAPS).map(({ field }) => [field, settled[field].size()]),
      ),
    }).filter(([, size]) => size !== 0n);
    if (leftovers.length > 0)
      throw new Error(
        `the vault kept ${JSON.stringify(leftovers, (_, v: unknown) => (typeof v === "bigint" ? String(v) : v))}`,
      );

    return {
      vaultAddress: this.vaultAddress,
      tronToken: tokenHex,
      operations: this.operations,
      lastSeen: { before, afterEthereum, afterTron },
      crossChainRefusals: { tronCompleteOfEthereum, ethereumCompleteOfTron },
      unsentRefund: { lateSendRefusal, waitedMs },
      recipient: {
        address: bytesToHex(recipient),
        before: Number(recipientBefore),
        after: Number(recipientAfter),
      },
    };
  }

  close(): void {
    this.evm.provider.destroy();
  }
}

// The error a call the vault must refuse fails with.
async function refusal(attempt: () => Promise<unknown>): Promise<string> {
  try {
    await attempt();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("the vault accepted a call it must refuse");
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

/**
 * Deploys the vault, queues and flushes a deposit, then sends it in a partially successful
 * transaction: CertiK SNA-07's shape.
 */
export async function runVaultPartialSend(input: VaultRunInput): Promise<VaultPartialSendResult> {
  const run = new VaultRun(input);
  try {
    await run.deployAndInitialise();
    return await run.partialSend();
  } finally {
    run.close();
  }
}

/**
 * Deploys the vault against local EVM targets and a TRE chain, then runs an ETH and a Tron
 * deposit and withdraw side by side.
 */
export async function runVaultTron(input: VaultRunInput): Promise<VaultTronRunResult> {
  const run = new VaultRun(input);
  try {
    await run.deployAndInitialise();
    return await run.runTron();
  } finally {
    run.close();
  }
}
