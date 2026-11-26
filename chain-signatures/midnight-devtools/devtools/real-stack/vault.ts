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
  evmAddressAbiWord,
  EvmTraceOutputKind,
  evmTraceOutputFromTronReceipt,
  executedEvmRespondOutput,
  getSolidifiedTronReferenceBlock,
  hexToBytes,
  isEvmContractCall,
  numericAbiWord,
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
import {
  readLendArtifact,
  readTronArtifact,
  TronChain,
  tronCost,
  type TronCost,
} from "./vault-tron.js";

type VaultHandle = FoundContract<VaultContract>;
type VaultLedger = ReturnType<typeof ledger>;

/** Each action's request map: its ledger field and compiled ledger path. */
const REQUEST_MAPS = {
  [Action.approve]: { field: "bidirectionalApproveMap", path: [2, 4] },
  [Action.deposit]: { field: "bidirectionalDepositMap", path: [2, 6] },
  [Action.tronDeposit]: { field: "bidirectionalTronDepositMap", path: [2, 8] },
  [Action.withdraw]: { field: "bidirectionalWithdrawMap", path: [2, 10] },
  [Action.swap]: { field: "bidirectionalSwapMap", path: [2, 12] },
  [Action.supply]: { field: "bidirectionalSupplyMap", path: [2, 14] },
  [Action.redeem]: { field: "bidirectionalRedeemMap", path: [3, 1] },
  [Action.tronWithdraw]: { field: "bidirectionalTronWithdrawMap", path: [3, 4] },
  [Action.tronApprove]: { field: "bidirectionalTronApproveMap", path: [3, 9] },
  [Action.tronSupply]: { field: "bidirectionalTronSupplyMap", path: [3, 11] },
  [Action.tronRedeem]: { field: "bidirectionalTronRedeemMap", path: [3, 13] },
} as const;
const TRON_ACTIONS: readonly VaultAction[] = [
  Action.tronDeposit,
  Action.tronWithdraw,
  Action.tronApprove,
  Action.tronSupply,
  Action.tronRedeem,
];
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
// still clear after proving; the unsent requests' refunds open about eleven minutes after
// their start, while the other requests run.
const TRON_UNSENT_WINDOW_MS = 720_000n;
// The Tron lend pair: a USDT-like underlying listed unshifted, and an ERC-4626 over it with
// 18-decimal shares listed with factor 10^12, so one share coin unit is 10^12 shares.
const SHARE_FACTOR = 10n ** 12n;
const TRON_USDT_SUPPLY = 10n ** 15n;
// The funder's own deposit and donation give the shares an exchange rate under which a
// supply leaves a remainder below one share coin unit.
const LEND_SEED = 60_000_000n;
const LEND_SEED_DONATION = 123_457n;
const TRON_USDT_DEPOSIT = 300_000_000n;
// 100 USDT, whose shares exceed 2^64 base units.
const TRON_SUPPLY_AMOUNT = 100_000_000n;
const TRON_MIN_SUPPLY = 1_000_000n;
const TRON_SUPPLY_FEE = 1_000n;
// What each refused, unviable and unsent supply and redeem surrenders.
const TRON_SMALL_SUPPLY = 10_000_000n;
const TRON_SMALL_REDEEM = 5_000_000n;
const TRON_REDEEM_FEE = 1_000n;
// Share coin units the user deposits from Tron, and withdraws back to Tron.
const TRON_SHARE_DEPOSIT = 50_000_000n;
const TRON_SHARE_WITHDRAW = 20_000_000n;
// Donated to the share token before the redeem, so the redeemed assets exceed the supply.
const TRON_LEND_YIELD = 10_000_000n;
// 1 TRX: TRE refuses a supply's broadcast at this limit, in pre-execution.
const TRON_STARVED_FEE_LIMIT = 1_000_000n;
// The starved supply's and the unbroadcast redeem's windows, sent first after their starts;
// the MPC attests them unviable once they close.
const TRON_SHORT_WINDOW_MS = 1_200_000n;
const UNVIABLE_TIMEOUT_MS = 30 * 60_000;

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
  /** The attested verdict: `executed`, `failed` or `unviable`. */
  outcome: string;
  /** Serialized output the attestation signs, hex (empty unless executed). */
  output: string;
  /** What the Tron transaction cost, when TRE included it. */
  tronCost?: TronCost;
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

/** The Tron lend pair: 21-byte addresses. */
interface TronLend {
  underlying: Uint8Array;
  share: Uint8Array;
}

/** A Tron request's TaPoS reference and validity window. */
interface TronWindow {
  refBlockBytes: Uint8Array;
  refBlockHash: Uint8Array;
  timestamp: bigint;
  expiration: bigint;
}

/** A Tron request to execute, between optional steps on TRE. */
interface TronStep {
  request: SentRequest;
  before?: () => Promise<void>;
  after?: () => Promise<void>;
}

/** One scenario's verdict, for the report. */
export interface TronScenario {
  name: string;
  expected: string;
  observed: string;
  /** From the scenario's first start to its settlement. */
  wallMs: number;
}

/** The Tron lend legs' amounts, base units as decimal strings. */
export interface TronLendResult {
  /** 21-byte hex. */
  underlying: string;
  shareToken: string;
  shareFactor: string;
  supply: {
    amount: string;
    calldataAmount: string;
    shares: string;
    minted: string;
    remainder: string;
    /** The trailing calldata word after `deposit`'s two arguments: the request's binding, 32-byte hex. */
    binding: string;
    /** `ownershipCommitment(inIndex, user secret)` of the request's start, 32-byte hex. */
    expectedBinding: string;
  };
  redeem: {
    shares: string;
    calldataShares: string;
    assets: string;
    /** The trailing calldata word after `redeem`'s three arguments, as the supply's. */
    binding: string;
    /** `ownershipCommitment(inIndex, user secret)` of the request's start, 32-byte hex. */
    expectedBinding: string;
  };
  shareDeposit: { amount: string; calldataAmount: string };
  shareWithdraw: {
    amount: string;
    calldataAmount: string;
    received: string;
    /** The trailing calldata word after `transfer`'s two arguments, as the supply's. */
    binding: string;
    /** `ownershipCommitment(inIndex, user secret)` of the request's start, 32-byte hex. */
    expectedBinding: string;
  };
  starvedSupply: { feeLimit: string; broadcastRefusal: string };
  /**
   * The vault's Tron balances and the coins of each colour, the fee recipient's included,
   * at the end.
   */
  backing: {
    underlyingVault: string;
    underlyingCoins: string;
    shareVault: string;
    shareCoins: string;
  };
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
   * The last-seen heights before the second round's attestations, after its ETH ones alone
   * are flushed, and after its Tron ones are flushed too.
   */
  lastSeen: {
    before: LastSeen;
    afterEthereum: LastSeen;
    afterTron: LastSeen;
    ethereumFlushed: string[];
    tronFlushed: string[];
  };
  /** The refusals of each chain's attestation presented to the other chain's complete. */
  crossChainRefusals: { tronCompleteOfEthereum: string; ethereumCompleteOfTron: string };
  /** The withdraw recipient's TRC-20 balance around the withdraw. */
  recipient: { address: string; before: number; after: number };
  /**
   * A Tron withdraw, supply and redeem left unsent until their windows closed to sends: the
   * late sends' refusals, and the refunds that re-minted their amounts.
   */
  unsentRefund: { lateSendRefusal: string; waitedMs: number };
  /**
   * The executed Tron withdraw's trailing calldata word after `transfer`'s two arguments,
   * and the ownership commitment of its start, which it must equal: 32-byte hex each.
   */
  withdrawBinding: { binding: string; expectedBinding: string };
  tronLend: TronLendResult;
  scenarios: TronScenario[];
}

/** What a Tron request's transaction does on TRE, which fixes the verdict the MPC attests. */
enum TronFate {
  /** Executes and returns true, or the data its schema names. */
  Executes = "executes",
  /** Executes, and the token reports success as false, as Tron USDT does. */
  ExecutesReturningFalse = "executesReturningFalse",
  /** Reverts: attested failed. */
  Reverts = "reverts",
  /** The node refuses the broadcast: attested unviable once the window closes. */
  BroadcastRefused = "broadcastRefused",
  /** Signed and never broadcast: attested unviable once the window closes. */
  NeverBroadcast = "neverBroadcast",
}

/** A request its start circuit queued under `inIndex`. */
interface StartedRequest {
  operation: string;
  action: VaultAction;
  inIndex: bigint;
  /** The account the MPC signs the request's transaction with: EVM hex, or Tron 21-byte hex. */
  signer: string;
  outputSchema: Uint8Array;
  /** A Tron request's fate; Executes when absent. */
  fate?: TronFate;
}

interface SentRequest extends StartedRequest {
  requestId: RequestIdHex;
  placement: CallPlacement[];
  /** When the send that notified the request finalised. */
  sentAt: number;
}

/** A request whose transaction reached its fate, with the verdict and output the MPC must attest. */
interface ExecutedRequest extends SentRequest {
  transaction: string;
  /** The including block; for an unviable request, set from its attestation. */
  blockHeight: number;
  outcome: OutputKind;
  decoded: Record<string, unknown>;
  output: Uint8Array;
  /** The signed transaction's calldata, hex. */
  calldata: string;
  tronCost?: TronCost;
  /** The node's refusal of a BroadcastRefused request's broadcast. */
  broadcastRefusal?: string;
  signedAt: number;
  broadcastAt: number;
}

interface AttestedRequest extends ExecutedRequest {
  event: RespondBidirectionalEvent;
}

const diagnostics = (message: string) => process.stderr.write(`vault: ${message}\n`);

// JSON.stringify replacer for ledger values.
const bigintJson = (_: string, value: unknown): unknown =>
  typeof value === "bigint" ? String(value) : value;

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// The ABI word `index` of hex calldata, after its 4-byte selector.
function calldataWord(calldata: string, index: number): bigint {
  const hex = calldata.replace(/^0x/i, "");
  const word = hex.slice(8 + index * 64, 8 + (index + 1) * 64);
  if (word.length !== 64) throw new Error(`calldata ${calldata} has no word ${index}`);
  return BigInt(`0x${word}`);
}

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

async function poll<T>(
  description: string,
  read: () => Promise<T | undefined>,
  timeoutMs = 480_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
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
  /** The vault's Tron USDT, which initialise records; 21-byte. */
  private tronUsdt: Uint8Array | undefined;
  /** Each listed Tron token's coin colour (domain separator), keyed by its 21-byte hex. */
  private readonly tronColours = new Map<string, Uint8Array>();
  private readonly scenarios: TronScenario[] = [];

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

  // A listed TRC-20's coin colour (domain separator) as hex: the one its listing stored.
  private tronColour(token: string): string {
    const colour = this.tronColours.get(token);
    if (colour === undefined) throw new Error(`Tron token ${token} is not listed`);
    return bytesToHex(colour);
  }

  // An ERC20's vault coin colour, or a TRC-20's (`token` then 21-byte hex) on the Tron chain.
  private tokenType(token: string, chain = TargetChain.Ethereum): string {
    return rawTokenType(
      chain === TargetChain.Tron
        ? hexToBytes(this.tronColour(token))
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
    // initialise records the Tron USDT, whose transfer reports success as false.
    this.tronUsdt =
      this.tron &&
      (await this.tron.deploy(
        await readLendArtifact("MidnightVaultTronUsdt"),
        numericAbiWord(TRON_USDT_SUPPLY),
      ));
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
    // Fees are taken on Tron requests only; their fee coins go to the deployer wallet.
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
      this.tronUsdt?.subarray(1) ?? new Uint8Array(20),
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
      case Action.tronApprove:
        return calls.sendTronApprove;
      case Action.tronSupply:
        return calls.sendTronSupply;
      case Action.tronRedeem:
        return calls.sendTronRedeem;
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
        outcome: OutputKind.executed,
        calldata: transaction.data,
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
  // derived owner, then brings about the request's fate: broadcasts the transaction (unless
  // it must never be) and rebuilds the output the MPC attests from its solidified receipt.
  private async executeTron(request: SentRequest): Promise<ExecutedRequest> {
    const tron = this.tronChain();
    const fate = request.fate ?? TronFate.Executes;
    const reader = this.reader(request.action);
    const record = await reader.getTronTriggerSmartContractSignatureRequest(request.requestId);
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
    const calldata = assembleCalldata(record.txParams.calldata);
    const pending = {
      ...request,
      transaction: bytesToHex(unsigned.txId),
      blockHeight: 0,
      outcome: OutputKind.unviable,
      decoded: {},
      output: new Uint8Array(),
      calldata,
      signedAt,
    };
    const broadcastAt = Date.now();
    if (fate === TronFate.NeverBroadcast) {
      diagnostics(`${request.operation} signed ${pending.transaction}, left unbroadcast`);
      return { ...pending, broadcastAt };
    }
    let broadcast: TronBroadcastOutcome;
    try {
      broadcast = await broadcastTronTransaction(tron.rpcUrl, signedTransaction);
    } catch (error) {
      const refusal = error instanceof Error ? error.message : String(error);
      if (fate !== TronFate.BroadcastRefused) throw error;
      diagnostics(`${request.operation} broadcast refused: ${refusal}`);
      return { ...pending, broadcastRefusal: refusal, broadcastAt };
    }
    diagnostics(
      `${request.operation} broadcast ${pending.transaction}: ${TronBroadcastOutcome[broadcast]}`,
    );
    if (fate === TronFate.BroadcastRefused) {
      throw new Error(`${request.operation}'s broadcast was not refused`);
    }
    const receipt = await tron.receipt(unsigned.txId);
    const tronCostOf = tronCost(receipt);
    const result = tronReceiptExecutionResult(receipt);
    diagnostics(
      `${request.operation} ran ${tronCostOf.result} in Tron block ${receipt.blockNumber}: ${tronCostOf.energy} energy, ${tronCostOf.fee} sun`,
    );
    const executed = { ...pending, blockHeight: Number(receipt.blockNumber), tronCost: tronCostOf };
    if (fate === TronFate.Reverts) {
      if (result !== TronExecutionResult.Failed) {
        throw new Error(`${request.operation} ran ${tronCostOf.result}, not a failure`);
      }
      return { ...executed, outcome: OutputKind.failed, broadcastAt };
    }
    if (result !== TronExecutionResult.Succeeded) {
      throw new Error(`${request.operation} ran ${tronCostOf.result}`);
    }
    const output = executedEvmRespondOutput(
      record.outputDeserializationSchema,
      isEvmContractCall(calldata),
      evmTraceOutputFromTronReceipt(receipt.body),
    );
    const decoded = deserializeEvmOutput(
      request.outputSchema,
      receipt.contractResult.at(0) ?? new Uint8Array(),
    );
    const returnsFalse = fate === TronFate.ExecutesReturningFalse;
    if ("success" in decoded && decoded.success !== !returnsFalse) {
      throw new Error(`${request.operation} returned ${String(decoded.success)}`);
    }
    return { ...executed, outcome: OutputKind.executed, decoded, output, broadcastAt };
  }

  // Waits for an attestation of the request's verdict that verifies against the response
  // key: at the executed or failed transaction's height, or, for an unviable request, at the
  // height it names, which then becomes the request's.
  private async attest(request: ExecutedRequest, timeoutMs?: number): Promise<AttestedRequest> {
    const event = await poll(
      `${request.operation} attestation`,
      () =>
        this.reader(request.action).getVerifiedRespondBidirectionalEvent(
          request.requestId,
          request.output,
          this.responseKey,
        ),
      timeoutMs,
    );
    const attestedAt = Date.now();
    if (event.outputKind !== request.outcome) {
      throw new Error(
        `${request.operation} attested ${OutputKind[event.outputKind]}, not ${OutputKind[request.outcome]}`,
      );
    }
    const blockHeight =
      request.outcome === OutputKind.unviable ? Number(event.blockHeight) : request.blockHeight;
    if (event.blockHeight !== BigInt(blockHeight)) {
      throw new Error(`${request.operation} attested height ${event.blockHeight}`);
    }
    diagnostics(
      `${request.operation} attested ${OutputKind[event.outputKind]} at height ${blockHeight}`,
    );
    this.operations.push({
      operation: request.operation,
      chain: TRON_ACTIONS.includes(request.action) ? TargetChain.Tron : TargetChain.Ethereum,
      requestId: request.requestId,
      placement: request.placement,
      transaction: request.transaction,
      blockHeight,
      outcome: OutputKind[event.outputKind],
      output: bytesToHex(request.output),
      tronCost: request.tronCost,
      sendToSignatureMs: request.signedAt - request.sentAt,
      broadcastToAttestationMs: attestedAt - request.broadcastAt,
    });
    return { ...request, blockHeight, event };
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

  // The fee recipient's keys, which a start minting a fee coin needs for its output.
  private async feeRecipientKeys(): Promise<Map<string, string>> {
    const configured = await this.readLedger();
    return new Map([
      [
        bytesToHex(configured.feeRecipientCoinPublicKey.bytes),
        bytesToHex(configured.feeRecipientEncryptionPublicKey),
      ],
    ]);
  }

  // Starts a Tron withdraw of `amount` units of `token` (plus its withdraw fee) to
  // `recipient` (21-byte) under a fresh window `windowMs` long, and returns that window.
  private async startTronWithdraw(
    inIndex: bigint,
    token: Uint8Array,
    amount: bigint,
    recipient: Uint8Array,
    windowMs: bigint,
  ): Promise<TronWindow> {
    await this.input.userFacade.waitForSyncedState();
    const fee = (await this.readLedger()).allowedTronTokens.lookup(token.subarray(1)).fees.withdraw;
    const window = await this.tronWindow(windowMs);
    await submitCallTx(this.providers, {
      ...createCallTxOptions(
        vaultCompiledContract,
        "startTronWithdraw",
        this.vaultAddress,
        VAULT_PRIVATE_STATE_ID,
        await this.feeRecipientKeys(),
        [
          inIndex,
          { tokenAddress: token.subarray(1), amount, destTronAddress: recipient.subarray(1) },
          window,
          this.coin(bytesToHex(token), amount + fee, TargetChain.Tron),
        ],
      ),
      privateStateId: VAULT_PRIVATE_STATE_ID,
    });
    return window;
  }

  // Starts a Tron supply of `amount` underlying units plus the supply fee.
  private async startTronSupply(
    inIndex: bigint,
    lend: TronLend,
    amount: bigint,
    windowMs: bigint,
  ): Promise<TronWindow> {
    await this.input.userFacade.waitForSyncedState();
    const window = await this.tronWindow(windowMs);
    await submitCallTx(this.providers, {
      ...createCallTxOptions(
        vaultCompiledContract,
        "startTronSupply",
        this.vaultAddress,
        VAULT_PRIVATE_STATE_ID,
        await this.feeRecipientKeys(),
        [
          inIndex,
          { amount },
          window,
          this.coin(bytesToHex(lend.underlying), amount + TRON_SUPPLY_FEE, TargetChain.Tron),
        ],
      ),
      privateStateId: VAULT_PRIVATE_STATE_ID,
    });
    return window;
  }

  // Starts a Tron redeem of `shares` share units plus the redeem fee.
  private async startTronRedeem(
    inIndex: bigint,
    lend: TronLend,
    shares: bigint,
    windowMs: bigint,
  ): Promise<TronWindow> {
    await this.input.userFacade.waitForSyncedState();
    const window = await this.tronWindow(windowMs);
    await submitCallTx(this.providers, {
      ...createCallTxOptions(
        vaultCompiledContract,
        "startTronRedeem",
        this.vaultAddress,
        VAULT_PRIVATE_STATE_ID,
        await this.feeRecipientKeys(),
        [
          inIndex,
          { shares },
          window,
          this.coin(bytesToHex(lend.share), shares + TRON_REDEEM_FEE, TargetChain.Tron),
        ],
      ),
      privateStateId: VAULT_PRIVATE_STATE_ID,
    });
    return window;
  }

  private async tronWindow(windowMs = TRON_WINDOW_MS): Promise<TronWindow> {
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

  // Lists a Tron token with its fees and factor, and keeps the colour the vault stored for
  // its coins, which must be tronCoinColour(token, factor).
  private async listTronToken(token: Uint8Array, fees: TokenFees, factor: bigint): Promise<void> {
    await this.vault.callTx.addAllowedTronToken(token.subarray(1), fees, factor);
    const config = (await this.readLedger()).allowedTronTokens.lookup(token.subarray(1));
    const colour = pureCircuits.tronCoinColour(token.subarray(1), factor);
    if (config.factor !== factor || bytesToHex(config.colour) !== bytesToHex(colour)) {
      throw new Error(`the vault listed ${bytesToHex(token)} with another factor or colour`);
    }
    this.tronColours.set(bytesToHex(token), config.colour);
  }

  // The ID the flush gave the request queued under `inIndex` for `action`.
  private async outIndexOf(action: VaultAction, inIndex: bigint): Promise<Uint8Array> {
    const outIndex = [...(await this.readLedger()).outputRequestBuffer].find(
      ([, { entry }]) => entry.action === action && entry.inIndex === inIndex,
    )?.[0];
    if (outIndex === undefined) throw new Error(`the flush did not move ${Action[action]}`);
    return outIndex;
  }

  // Sets the vault's Tron supply fee limit, keeping every other gas setting, and returns the
  // limit it replaced.
  private async setTronSupplyFeeLimit(supply: bigint): Promise<bigint> {
    const state = await this.readLedger();
    const limits = state.vaultGasLimits;
    await this.vault.callTx.setGasParams(
      state.vaultMaxFeePerGas,
      state.vaultMaxPriorityFeePerGas,
      limits.withdraw,
      limits.approve,
      limits.swap,
      limits.supply,
      limits.redeem,
      { ...state.vaultTronFeeLimits, supply },
    );
    return state.vaultTronFeeLimits.supply;
  }

  // Executes the ETH requests, and beside them the Tron steps in order, each between its
  // own before and after steps, while TRE packs blocks. Waits for every attestation except
  // the unviable ones', which only come once their windows close.
  private async settleRound(
    ethereum: readonly SentRequest[],
    tronSteps: readonly TronStep[],
  ): Promise<{ attested: Map<string, AttestedRequest>; unviable: ExecutedRequest[] }> {
    const [ethereumAttested, tron] = await Promise.all([
      (async () => {
        const attested: AttestedRequest[] = [];
        for (const request of ethereum.length > 0 ? await this.executeEvm(ethereum) : []) {
          attested.push(await this.attest(request));
        }
        return attested;
      })(),
      this.tronChain().withBlocks(async () => {
        const executed: ExecutedRequest[] = [];
        for (const step of tronSteps) {
          await step.before?.();
          executed.push(await this.executeTron(step.request));
          await step.after?.();
        }
        const settled = executed.filter((request) => request.outcome !== OutputKind.unviable);
        return {
          attested: await Promise.all(settled.map(async (request) => this.attest(request))),
          unviable: executed.filter((request) => request.outcome === OutputKind.unviable),
        };
      }),
    ]);
    return {
      attested: new Map(
        [...ethereumAttested, ...tron.attested].map((request) => [request.operation, request]),
      ),
      unviable: tron.unviable,
    };
  }

  // Records a scenario's outcome with its wall time from its first start.
  private scenario(name: string, expected: string, observed: string, startedAt: number): void {
    const wallMs = Date.now() - startedAt;
    diagnostics(`scenario ${name}: ${observed} (${wallMs} ms)`);
    this.scenarios.push({ name, expected, observed, wallMs });
  }

  /**
   * Tron lend beside ETH lend, and the Tron deposit and withdraw of an unshifted TRC-20
   * beside an ETH deposit and withdraw. A USDT-like underlying (listed unshifted, the vault's
   * Tron USDT) and an ERC-4626 over it with 18-decimal shares (listed with factor 10^12) form
   * the lend pair. Every Tron verdict is reached: executed supplies, redeems, deposits and
   * withdraws; a supply against a paused share token and a redeem with no cash left, failed
   * and refunded; a supply whose fee limit TRE refuses and a redeem signed but never
   * broadcast, unviable and refunded; a withdraw, a supply and a redeem never sent, refunded
   * once their windows close to sends. Each chain's attestations fold only into its own
   * last-seen height, and each chain's attestation is offered to the other chain's complete.
   */
  async runTron(): Promise<VaultTronRunResult> {
    const tron = this.tronChain();
    const gateArtifact = this.input.tron?.tokenArtifact;
    if (gateArtifact === undefined) throw new Error("this run has no Tron token artifact");
    const usdt = this.tronUsdt;
    if (usdt === undefined) throw new Error("the vault was initialised without a Tron USDT");
    const transferSchema = pureCircuits.vaultOutputSchema();
    const { usdc, stata } = this.targets;
    const wallet = this.input.userFacade;
    const userTron = tronAddressFromEvm(this.userEvm);
    const vaultTron = tronAddressFromEvm(this.vaultEvm);
    const vaultWord = evmAddressAbiWord(vaultTron.subarray(1));
    const noRecipient = {
      is_some: false,
      value: {
        is_left: true,
        left: { bytes: new Uint8Array(32) },
        right: { bytes: new Uint8Array(32) },
      },
    };
    const noOutput = new Uint8Array(32);
    const started = new Map<string, number>();
    const start = (
      operation: string,
      action: VaultAction,
      signer: string,
      outputSchema: Uint8Array,
      fate?: TronFate,
    ): StartedRequest => {
      started.set(operation, Date.now());
      return { operation, action, inIndex: newInputIndex(), signer, outputSchema, fate };
    };
    const startedAt = (operation: string): number => {
      const at = started.get(operation);
      if (at === undefined) throw new Error(`${operation} never started`);
      return at;
    };

    diagnostics(
      "deploying the TRC-20 and the share token, listing them, funding the Tron accounts",
    );
    const gate = await tron.deploy(await readTronArtifact(gateArtifact));
    const gateHex = bytesToHex(gate);
    const share = await tron.deploy(
      await readLendArtifact("MidnightVaultTronLend"),
      evmAddressAbiWord(usdt.subarray(1)),
    );
    const lend: TronLend = { underlying: usdt, share };
    const usdtHex = bytesToHex(usdt);
    const shareHex = bytesToHex(share);
    await this.listTronToken(gate, { ...NO_FEES, withdraw: TRON_WITHDRAW_FEE }, 1n);
    await this.listTronToken(usdt, { ...NO_FEES, supply: TRON_SUPPLY_FEE }, 1n);
    await this.listTronToken(share, { ...NO_FEES, redeem: TRON_REDEEM_FEE }, SHARE_FACTOR);
    if (
      this.tronColour(usdtHex) !==
        bytesToHex(pureCircuits.vaultTronTokenDomainSeparator(usdt.subarray(1))) ||
      this.tronColour(shareHex) ===
        bytesToHex(pureCircuits.vaultTronTokenDomainSeparator(share.subarray(1)))
    ) {
      throw new Error(
        "an unshifted token changed colour, or the shifted one kept the unshifted colour",
      );
    }
    await this.vault.callTx.setTronLendPair(usdt.subarray(1), share.subarray(1), TRON_MIN_SUPPLY);
    await tron.sendTrx(userTron, TRON_ACCOUNT_TRX);
    await tron.sendTrx(vaultTron, TRON_ACCOUNT_TRX);
    await tron.sendToken(gate, userTron, TRON_DEPOSIT_AMOUNT);
    await tron.sendToken(usdt, userTron, TRON_USDT_DEPOSIT);
    // The funder's own deposit and donation give the shares an exchange rate whose supply
    // leaves a remainder, and the shares the user deposits.
    const funderWord = evmAddressAbiWord(tron.funder.subarray(1));
    await tron.trigger(
      usdt,
      "approve(address,uint256)",
      concat(evmAddressAbiWord(share.subarray(1)), numericAbiWord(TRON_USDT_SUPPLY)),
    );
    await tron.trigger(
      share,
      "deposit(uint256,address)",
      concat(numericAbiWord(LEND_SEED), funderWord),
    );
    await tron.sendToken(usdt, share, LEND_SEED_DONATION);
    await tron.sendToken(share, userTron, TRON_SHARE_DEPOSIT * SHARE_FACTOR);

    diagnostics("queueing the ETH deposit and approval, the Tron deposits and approval");
    const depositStart = start("deposit", Action.deposit, this.userEvm, transferSchema);
    const approveStart = start("approveStata", Action.approve, this.vaultEvm, transferSchema);
    const gateDepositStart = start(
      "tronDeposit",
      Action.tronDeposit,
      bytesToHex(userTron),
      transferSchema,
    );
    const usdtDepositStart = start(
      "tronDepositUsdt",
      Action.tronDeposit,
      bytesToHex(userTron),
      transferSchema,
      TronFate.ExecutesReturningFalse,
    );
    const shareDepositStart = start(
      "tronDepositShares",
      Action.tronDeposit,
      bytesToHex(userTron),
      transferSchema,
    );
    const tronApproveStart = start(
      "tronApprove",
      Action.tronApprove,
      bytesToHex(vaultTron),
      transferSchema,
    );
    await this.vault.callTx.startDeposit(
      depositStart.inIndex,
      BigInt(await this.evm.provider.getTransactionCount(this.userEvm)),
      DEPOSIT_GAS,
      { erc20Address: hexToBytes(usdc), amount: WITHDRAW_AMOUNT + SUPPLY_AMOUNT },
    );
    await this.vault.callTx.startApproveStata(approveStart.inIndex);
    for (const [request, token, amount] of [
      [gateDepositStart, gate, TRON_DEPOSIT_AMOUNT],
      [usdtDepositStart, usdt, TRON_USDT_DEPOSIT],
      [shareDepositStart, share, TRON_SHARE_DEPOSIT],
    ] as const) {
      await this.vault.callTx.startTronDeposit(
        request.inIndex,
        { ...(await this.tronWindow()), feeLimit: TRON_DEPOSIT_FEE_LIMIT },
        { tokenAddress: token.subarray(1), amount },
      );
    }
    await this.vault.callTx.startTronApprove(tronApproveStart.inIndex, await this.tronWindow());
    const openingSent = await this.flushAndSend([
      depositStart,
      approveStart,
      gateDepositStart,
      usdtDepositStart,
      shareDepositStart,
      tronApproveStart,
    ]);
    const sentOf = (sent: readonly SentRequest[], operation: string): SentRequest => {
      const request = sent.find((candidate) => candidate.operation === operation);
      if (request === undefined) throw new Error(`${operation} was not sent`);
      return request;
    };
    const vaultUsdcBefore = await this.evm.balanceOf(usdc, this.vaultEvm);
    const vaultBefore = {
      gate: await tron.balanceOf(gate, vaultTron),
      usdt: await tron.balanceOf(usdt, vaultTron),
      share: await tron.balanceOf(share, vaultTron),
    };
    const opening = await this.settleRound(
      [sentOf(openingSent, "deposit"), sentOf(openingSent, "approveStata")],
      ["tronDeposit", "tronDepositUsdt", "tronDepositShares", "tronApprove"].map((operation) => ({
        request: sentOf(openingSent, operation),
      })),
    );
    if (
      (await this.evm.balanceOf(usdc, this.vaultEvm)) - vaultUsdcBefore !==
      WITHDRAW_AMOUNT + SUPPLY_AMOUNT
    ) {
      throw new Error("the ETH deposit did not move the ERC20 into the vault account");
    }
    const shareDeposit = attestedOf(opening.attested, "tronDepositShares");
    if (
      (await tron.balanceOf(gate, vaultTron)) - vaultBefore.gate !== TRON_DEPOSIT_AMOUNT ||
      (await tron.balanceOf(usdt, vaultTron)) - vaultBefore.usdt !== TRON_USDT_DEPOSIT ||
      (await tron.balanceOf(share, vaultTron)) - vaultBefore.share !==
        TRON_SHARE_DEPOSIT * SHARE_FACTOR ||
      calldataWord(shareDeposit.calldata, 1) !== TRON_SHARE_DEPOSIT * SHARE_FACTOR
    ) {
      throw new Error("a Tron deposit did not move its base units into the vault's Tron account");
    }
    const allowance = await tron.read(
      usdt,
      "allowance(address,address)",
      concat(vaultWord, evmAddressAbiWord(share.subarray(1))),
    );
    if (allowance !== pureCircuits.unlimitedAllowance()) {
      throw new Error(`the Tron approval left an allowance of ${allowance}`);
    }
    await this.queueAndFlush([...opening.attested.values()]);
    const deposit = attestedOf(opening.attested, "deposit");
    await this.vault.callTx.completeDeposit(
      hexToBytes(deposit.requestId),
      deposit.output,
      randomBytes(32),
      noRecipient,
    );
    const approveStata = attestedOf(opening.attested, "approveStata");
    await this.vault.callTx.completeApprove(
      hexToBytes(approveStata.requestId),
      approveStata.output,
    );
    for (const operation of ["tronDeposit", "tronDepositUsdt", "tronDepositShares"]) {
      const tronDeposit = attestedOf(opening.attested, operation);
      await this.vault.callTx.completeTronDeposit(
        hexToBytes(tronDeposit.requestId),
        tronDeposit.output,
        randomBytes(32),
        noRecipient,
      );
    }
    const tronApprove = attestedOf(opening.attested, "tronApprove");
    await this.vault.callTx.completeTronApprove(
      hexToBytes(tronApprove.requestId),
      tronApprove.output,
    );
    for (const request of opening.attested.values()) await this.removed(request);
    let usdcCoins = WITHDRAW_AMOUNT + SUPPLY_AMOUNT;
    let gateCoins = TRON_DEPOSIT_AMOUNT;
    let usdtCoins = TRON_USDT_DEPOSIT;
    let shareCoins = TRON_SHARE_DEPOSIT;
    await this.expectBalance(usdc, usdcCoins);
    await this.expectBalance(gateHex, gateCoins, TargetChain.Tron);
    await this.expectBalance(usdtHex, usdtCoins, TargetChain.Tron);
    await this.expectBalance(shareHex, shareCoins, TargetChain.Tron);
    for (const [operation, request] of opening.attested) {
      const settles =
        request.action === Action.approve || request.action === Action.tronApprove
          ? "executed, request closed"
          : "executed, deposit minted";
      this.scenario(operation, settles, settles, startedAt(operation));
    }

    // Queued and flushed now, never sent: their refunds open while the other requests run.
    diagnostics(
      "queueing and flushing a Tron withdraw, supply and redeem nobody will send in time",
    );
    const unsent = {
      withdraw: { inIndex: newInputIndex(), action: Action.tronWithdraw as VaultAction },
      supply: { inIndex: newInputIndex(), action: Action.tronSupply as VaultAction },
      redeem: { inIndex: newInputIndex(), action: Action.tronRedeem as VaultAction },
    };
    const unsentStartedAt = Date.now();
    const unsentWindows = [
      await this.startTronWithdraw(
        unsent.withdraw.inIndex,
        gate,
        TRON_WITHDRAW_AMOUNT,
        tronAddressFromEvm(randomBytes(20)),
        TRON_UNSENT_WINDOW_MS,
      ),
      await this.startTronSupply(
        unsent.supply.inIndex,
        lend,
        TRON_SMALL_SUPPLY,
        TRON_UNSENT_WINDOW_MS,
      ),
      await this.startTronRedeem(
        unsent.redeem.inIndex,
        lend,
        TRON_SMALL_REDEEM,
        TRON_UNSENT_WINDOW_MS,
      ),
    ];
    gateCoins -= TRON_WITHDRAW_AMOUNT + TRON_WITHDRAW_FEE;
    usdtCoins -= TRON_SMALL_SUPPLY + TRON_SUPPLY_FEE;
    shareCoins -= TRON_SMALL_REDEEM + TRON_REDEEM_FEE;
    await this.flush(
      Object.values(unsent).map((request) => request.inIndex),
      [],
    );
    const unsentOut = {
      withdraw: await this.outIndexOf(unsent.withdraw.action, unsent.withdraw.inIndex),
      supply: await this.outIndexOf(unsent.supply.action, unsent.supply.inIndex),
      redeem: await this.outIndexOf(unsent.redeem.action, unsent.redeem.inIndex),
    };

    diagnostics(
      "queueing the ETH withdraw and supply beside the Tron withdraws, supplies and redeems",
    );
    const vaultSigner = bytesToHex(vaultTron);
    const supplySchema = pureCircuits.supplyOutputSchema();
    const redeemSchema = pureCircuits.redeemOutputSchema();
    const withdrawStart = start("withdraw", Action.withdraw, this.vaultEvm, transferSchema);
    const supplyStart = start("supply", Action.supply, this.vaultEvm, supplySchema);
    const tronWithdrawStart = start(
      "tronWithdraw",
      Action.tronWithdraw,
      vaultSigner,
      transferSchema,
    );
    const tronSupplyStart = start("tronSupply", Action.tronSupply, vaultSigner, supplySchema);
    const pausedSupplyStart = start(
      "tronSupplyPaused",
      Action.tronSupply,
      vaultSigner,
      supplySchema,
      TronFate.Reverts,
    );
    const noCashRedeemStart = start(
      "tronRedeemNoCash",
      Action.tronRedeem,
      vaultSigner,
      redeemSchema,
      TronFate.Reverts,
    );
    const shareWithdrawStart = start(
      "tronWithdrawShares",
      Action.tronWithdraw,
      vaultSigner,
      transferSchema,
    );
    const recipient = tronAddressFromEvm(randomBytes(20));
    const shareRecipient = tronAddressFromEvm(randomBytes(20));
    const recipientBefore = await tron.balanceOf(gate, recipient);
    await this.vault.callTx.startWithdraw(
      withdrawStart.inIndex,
      {
        erc20Address: hexToBytes(usdc),
        amount: WITHDRAW_AMOUNT,
        destEvmAddress: hexToBytes(this.userEvm),
      },
      this.coin(usdc, WITHDRAW_AMOUNT),
    );
    await wallet.waitForSyncedState();
    await this.vault.callTx.startSupply(
      supplyStart.inIndex,
      { amount: SUPPLY_AMOUNT },
      this.coin(usdc, SUPPLY_AMOUNT),
    );
    usdcCoins -= WITHDRAW_AMOUNT + SUPPLY_AMOUNT;
    await this.startTronWithdraw(
      tronWithdrawStart.inIndex,
      gate,
      TRON_WITHDRAW_AMOUNT,
      recipient,
      TRON_WINDOW_MS,
    );
    await this.startTronSupply(tronSupplyStart.inIndex, lend, TRON_SUPPLY_AMOUNT, TRON_WINDOW_MS);
    await this.startTronSupply(pausedSupplyStart.inIndex, lend, TRON_SMALL_SUPPLY, TRON_WINDOW_MS);
    await this.startTronRedeem(noCashRedeemStart.inIndex, lend, TRON_SMALL_REDEEM, TRON_WINDOW_MS);
    await this.startTronWithdraw(
      shareWithdrawStart.inIndex,
      share,
      TRON_SHARE_WITHDRAW,
      shareRecipient,
      TRON_WINDOW_MS,
    );
    gateCoins -= TRON_WITHDRAW_AMOUNT + TRON_WITHDRAW_FEE;
    usdtCoins -= TRON_SUPPLY_AMOUNT + TRON_SUPPLY_FEE + TRON_SMALL_SUPPLY + TRON_SUPPLY_FEE;
    shareCoins -= TRON_SMALL_REDEEM + TRON_REDEEM_FEE + TRON_SHARE_WITHDRAW;
    // Started last and sent first: their windows close soonest. The starved supply keeps the
    // fee limit it started under, so the limit is restored right after its start.
    const starvedSupplyStart = start(
      "tronSupplyStarved",
      Action.tronSupply,
      vaultSigner,
      supplySchema,
      TronFate.BroadcastRefused,
    );
    const supplyFeeLimit = await this.setTronSupplyFeeLimit(TRON_STARVED_FEE_LIMIT);
    await this.startTronSupply(
      starvedSupplyStart.inIndex,
      lend,
      TRON_SMALL_SUPPLY,
      TRON_SHORT_WINDOW_MS,
    );
    await this.setTronSupplyFeeLimit(supplyFeeLimit);
    const unbroadcastRedeemStart = start(
      "tronRedeemUnbroadcast",
      Action.tronRedeem,
      vaultSigner,
      redeemSchema,
      TronFate.NeverBroadcast,
    );
    await this.startTronRedeem(
      unbroadcastRedeemStart.inIndex,
      lend,
      TRON_SMALL_REDEEM,
      TRON_SHORT_WINDOW_MS,
    );
    usdtCoins -= TRON_SMALL_SUPPLY + TRON_SUPPLY_FEE;
    shareCoins -= TRON_SMALL_REDEEM + TRON_REDEEM_FEE;
    const legsSent = await this.flushAndSend([
      starvedSupplyStart,
      unbroadcastRedeemStart,
      withdrawStart,
      supplyStart,
      tronWithdrawStart,
      tronSupplyStart,
      pausedSupplyStart,
      noCashRedeemStart,
      shareWithdrawStart,
    ]);
    const userUsdcBefore = await this.evm.balanceOf(usdc, this.userEvm);
    const vaultBeforeLegs = {
      gate: await tron.balanceOf(gate, vaultTron),
      usdt: await tron.balanceOf(usdt, vaultTron),
      share: await tron.balanceOf(share, vaultTron),
    };
    let expectedShares = 0n;
    const setPaused = async (paused: boolean) => {
      await tron.trigger(share, "setPaused(bool)", numericAbiWord(paused ? 1n : 0n));
    };
    let lentCash = 0n;
    const legs = await this.settleRound(
      [sentOf(legsSent, "withdraw"), sentOf(legsSent, "supply")],
      [
        {
          request: sentOf(legsSent, "tronSupply"),
          before: async () => {
            expectedShares = await tron.read(
              share,
              "previewDeposit(uint256)",
              numericAbiWord(TRON_SUPPLY_AMOUNT),
            );
          },
        },
        {
          request: sentOf(legsSent, "tronSupplyPaused"),
          before: async () => setPaused(true),
          after: async () => setPaused(false),
        },
        {
          request: sentOf(legsSent, "tronRedeemNoCash"),
          before: async () => {
            lentCash = await tron.balanceOf(usdt, share);
            await tron.trigger(share, "lend(uint256)", numericAbiWord(lentCash));
          },
          after: async () => {
            await tron.sendToken(usdt, share, lentCash);
            await tron.trigger(share, "repay(uint256)", numericAbiWord(lentCash));
          },
        },
        { request: sentOf(legsSent, "tronWithdrawShares") },
        { request: sentOf(legsSent, "tronWithdraw") },
        { request: sentOf(legsSent, "tronSupplyStarved") },
        { request: sentOf(legsSent, "tronRedeemUnbroadcast") },
      ],
    );
    if ((await this.evm.balanceOf(usdc, this.userEvm)) - userUsdcBefore !== WITHDRAW_AMOUNT) {
      throw new Error("the ETH withdraw did not pay the destination");
    }
    const ethSupply = attestedOf(legs.attested, "supply");
    if (ethSupply.decoded.shares !== SUPPLY_AMOUNT) {
      throw new Error(`the ETH supply attested ${String(ethSupply.decoded.shares)} shares`);
    }
    const recipientAfter = await tron.balanceOf(gate, recipient);
    if (recipientAfter - recipientBefore !== TRON_WITHDRAW_AMOUNT) {
      throw new Error(`the Tron withdraw paid ${recipientAfter - recipientBefore}`);
    }
    const tronSupply = attestedOf(legs.attested, "tronSupply");
    const supplied = tronSupply.decoded.shares;
    if (typeof supplied !== "bigint" || supplied !== expectedShares || supplied <= 2n ** 64n) {
      throw new Error(
        `the Tron supply attested ${String(supplied)}, expected ${expectedShares} above 2^64`,
      );
    }
    const mintedShares = supplied / SHARE_FACTOR;
    const remainder = supplied - mintedShares * SHARE_FACTOR;
    const shareWithdraw = attestedOf(legs.attested, "tronWithdrawShares");
    const shareReceived = await tron.balanceOf(share, shareRecipient);
    if (
      calldataWord(tronSupply.calldata, 0) !== TRON_SUPPLY_AMOUNT ||
      calldataWord(shareWithdraw.calldata, 1) !== TRON_SHARE_WITHDRAW * SHARE_FACTOR ||
      shareReceived !== TRON_SHARE_WITHDRAW * SHARE_FACTOR
    ) {
      throw new Error(
        "a Tron supply or share withdraw moved other base units than its units times the factor",
      );
    }
    const vaultAfterLegs = {
      gate: await tron.balanceOf(gate, vaultTron),
      usdt: await tron.balanceOf(usdt, vaultTron),
      share: await tron.balanceOf(share, vaultTron),
    };
    if (
      vaultBeforeLegs.gate - vaultAfterLegs.gate !== TRON_WITHDRAW_AMOUNT ||
      vaultBeforeLegs.usdt - vaultAfterLegs.usdt !== TRON_SUPPLY_AMOUNT ||
      vaultAfterLegs.share - vaultBeforeLegs.share !== supplied - TRON_SHARE_WITHDRAW * SHARE_FACTOR
    ) {
      throw new Error(
        `the vault's Tron account moved ${JSON.stringify(vaultAfterLegs, bigintJson)}`,
      );
    }

    // Each chain's attestations fold only into its own last-seen height.
    const ethereumFlushed = ["withdraw", "supply"];
    const tronFlushed = [
      "tronWithdraw",
      "tronSupply",
      "tronSupplyPaused",
      "tronRedeemNoCash",
      "tronWithdrawShares",
    ];
    const heightOf = (operations: readonly string[]) =>
      Math.max(...operations.map((operation) => attestedOf(legs.attested, operation).blockHeight));
    const before = await this.lastSeen();
    if (heightOf(tronFlushed) <= before.tron) {
      throw new Error(
        `the Tron requests attested ${heightOf(tronFlushed)}, not above ${before.tron}`,
      );
    }
    await this.queueAndFlush(
      ethereumFlushed.map((operation) => attestedOf(legs.attested, operation)),
    );
    const afterEthereum = await this.lastSeen();
    const withdraw = attestedOf(legs.attested, "withdraw");
    const tronWithdraw = attestedOf(legs.attested, "tronWithdraw");
    if (
      afterEthereum.ethereum !== Math.max(before.ethereum, heightOf(ethereumFlushed)) ||
      afterEthereum.tron !== before.tron ||
      !(await this.readLedger()).bidirectionalTronWithdrawMap.member(
        hexToBytes(tronWithdraw.requestId),
      )
    ) {
      throw new Error(`the ETH flush moved ${JSON.stringify({ before, afterEthereum })}`);
    }
    await this.queueAndFlush(tronFlushed.map((operation) => attestedOf(legs.attested, operation)));
    const afterTron = await this.lastSeen();
    if (
      afterTron.tron !== Math.max(before.tron, heightOf(tronFlushed)) ||
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
    await this.vault.callTx.completeSupply(
      hexToBytes(ethSupply.requestId),
      ethSupply.output,
      randomBytes(32),
    );
    await this.vault.callTx.completeTronWithdraw(
      hexToBytes(tronWithdraw.requestId),
      tronWithdraw.output,
      randomBytes(32),
    );
    await this.vault.callTx.completeTronWithdraw(
      hexToBytes(shareWithdraw.requestId),
      shareWithdraw.output,
      randomBytes(32),
    );
    await this.vault.callTx.completeTronSupply(
      hexToBytes(tronSupply.requestId),
      tronSupply.output,
      randomBytes(32),
    );
    const pausedSupply = attestedOf(legs.attested, "tronSupplyPaused");
    await this.vault.callTx.completeTronSupply(
      hexToBytes(pausedSupply.requestId),
      noOutput,
      randomBytes(32),
    );
    const noCashRedeem = attestedOf(legs.attested, "tronRedeemNoCash");
    await this.vault.callTx.completeTronRedeem(
      hexToBytes(noCashRedeem.requestId),
      noOutput,
      randomBytes(32),
    );
    for (const operation of [...ethereumFlushed, ...tronFlushed]) {
      await this.removed(attestedOf(legs.attested, operation));
    }
    // The supply mints its floored shares; the refused supply and redeem re-mint what they
    // burned, less the fee.
    shareCoins += mintedShares + TRON_SMALL_REDEEM;
    usdtCoins += TRON_SMALL_SUPPLY;
    await this.expectBalance(usdc, usdcCoins);
    await this.expectBalance(stata, SUPPLY_AMOUNT);
    await this.expectBalance(gateHex, gateCoins, TargetChain.Tron);
    await this.expectBalance(usdtHex, usdtCoins, TargetChain.Tron);
    await this.expectBalance(shareHex, shareCoins, TargetChain.Tron);
    this.scenario(
      "withdraw",
      "executed, burn stands",
      "executed, burn stands",
      startedAt("withdraw"),
    );
    this.scenario(
      "supply",
      "executed, shares minted",
      `executed, ${SUPPLY_AMOUNT} shares minted`,
      startedAt("supply"),
    );
    this.scenario(
      "tronWithdraw",
      "executed, recipient paid",
      `executed, recipient +${TRON_WITHDRAW_AMOUNT}`,
      startedAt("tronWithdraw"),
    );
    this.scenario(
      "tronSupply",
      "executed, floor(shares / 10^12) minted, remainder < 10^12 kept on Tron",
      `executed, ${supplied} shares, ${mintedShares} minted, remainder ${remainder}`,
      startedAt("tronSupply"),
    );
    this.scenario(
      "tronSupplyPaused",
      "failed, underlying refunded, fee kept",
      `failed (${pausedSupply.tronCost?.result}), ${TRON_SMALL_SUPPLY} refunded, fee ${TRON_SUPPLY_FEE} kept`,
      startedAt("tronSupplyPaused"),
    );
    this.scenario(
      "tronRedeemNoCash",
      "failed, shares refunded, fee kept",
      `failed (${noCashRedeem.tronCost?.result}, ${lentCash} lent out), ${TRON_SMALL_REDEEM} refunded, fee ${TRON_REDEEM_FEE} kept`,
      startedAt("tronRedeemNoCash"),
    );
    this.scenario(
      "tronWithdrawShares",
      "executed, recipient paid units x 10^12",
      `executed, recipient +${shareReceived}`,
      startedAt("tronWithdrawShares"),
    );

    diagnostics("waiting for the starved supply's and the unbroadcast redeem's unviable verdicts");
    const unviable = await tron.withBlocks(async () =>
      Promise.all(legs.unviable.map(async (request) => this.attest(request, UNVIABLE_TIMEOUT_MS))),
    );
    await this.queueAndFlush(unviable);
    const starvedSupply = attestedOf(
      new Map(unviable.map((r) => [r.operation, r])),
      "tronSupplyStarved",
    );
    const unbroadcastRedeem = attestedOf(
      new Map(unviable.map((r) => [r.operation, r])),
      "tronRedeemUnbroadcast",
    );
    await this.vault.callTx.completeTronSupply(
      hexToBytes(starvedSupply.requestId),
      noOutput,
      randomBytes(32),
    );
    await this.vault.callTx.completeTronRedeem(
      hexToBytes(unbroadcastRedeem.requestId),
      noOutput,
      randomBytes(32),
    );
    await this.removed(starvedSupply);
    await this.removed(unbroadcastRedeem);
    usdtCoins += TRON_SMALL_SUPPLY;
    shareCoins += TRON_SMALL_REDEEM;
    await this.expectBalance(usdtHex, usdtCoins, TargetChain.Tron);
    await this.expectBalance(shareHex, shareCoins, TargetChain.Tron);
    const broadcastRefusal = starvedSupply.broadcastRefusal ?? "";
    this.scenario(
      "tronSupplyStarved",
      "out of energy: failed or unviable, underlying refunded, fee kept",
      `unviable at Tron ${starvedSupply.blockHeight} (broadcast refused: ${broadcastRefusal}), ${TRON_SMALL_SUPPLY} refunded`,
      startedAt("tronSupplyStarved"),
    );
    this.scenario(
      "tronRedeemUnbroadcast",
      "unviable, shares refunded, fee kept",
      `unviable at Tron ${unbroadcastRedeem.blockHeight}, ${TRON_SMALL_REDEEM} refunded`,
      startedAt("tronRedeemUnbroadcast"),
    );

    // From the expiration's whole seconds minus the send margin, each send is refused and the
    // requester's refund re-mints the amount; the fee stays taken.
    const refundOpensAt = Math.max(
      ...unsentWindows.map(
        (window) =>
          Number(window.expiration / 1000n - pureCircuits.tronSendMinRemainingSeconds()) * 1000,
      ),
    );
    diagnostics(`waiting for the unsent requests' refunds to open at ${refundOpensAt}`);
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, refundOpensAt - Date.now())));
    const lateSendRefusals = [
      await refusal(() => this.vault.callTx.sendTronWithdraw(unsentOut.withdraw)),
      await refusal(() => this.vault.callTx.sendTronSupply(unsentOut.supply)),
      await refusal(() => this.vault.callTx.sendTronRedeem(unsentOut.redeem)),
    ];
    if (lateSendRefusals.some((message) => !message.includes("too close"))) {
      throw new Error(`a late send failed otherwise: ${JSON.stringify(lateSendRefusals)}`);
    }
    await this.vault.callTx.refundUnsentTronWithdraw(unsent.withdraw.inIndex, randomBytes(32));
    await this.vault.callTx.refundUnsentTronSupply(unsent.supply.inIndex, randomBytes(32));
    await this.vault.callTx.refundUnsentTronRedeem(unsent.redeem.inIndex, randomBytes(32));
    const waitedMs = Date.now() - unsentStartedAt;
    gateCoins += TRON_WITHDRAW_AMOUNT;
    usdtCoins += TRON_SMALL_SUPPLY;
    shareCoins += TRON_SMALL_REDEEM;
    await this.expectBalance(gateHex, gateCoins, TargetChain.Tron);
    await this.expectBalance(usdtHex, usdtCoins, TargetChain.Tron);
    await this.expectBalance(shareHex, shareCoins, TargetChain.Tron);
    for (const name of ["tronWithdrawUnsent", "tronSupplyUnsent", "tronRedeemUnsent"]) {
      this.scenario(
        name,
        "late send refused, amount refunded, fee kept",
        'late send refused "too close", amount refunded',
        unsentStartedAt,
      );
    }

    diagnostics("queueing the ETH and Tron redeems after yield");
    const redeemStart = start("redeem", Action.redeem, this.vaultEvm, redeemSchema);
    const tronRedeemStart = start("tronRedeem", Action.tronRedeem, vaultSigner, redeemSchema);
    await this.vault.callTx.startRedeem(
      redeemStart.inIndex,
      { shares: SUPPLY_AMOUNT },
      this.coin(stata, SUPPLY_AMOUNT),
    );
    await this.startTronRedeem(tronRedeemStart.inIndex, lend, mintedShares, TRON_WINDOW_MS);
    shareCoins -= mintedShares + TRON_REDEEM_FEE;
    const redeemsSent = await this.flushAndSend([redeemStart, tronRedeemStart]);
    const vaultBeforeRedeem = {
      usdt: await tron.balanceOf(usdt, vaultTron),
      share: await tron.balanceOf(share, vaultTron),
    };
    // Yield on both chains before either redeem executes, so both return more than supplied.
    await this.evm.mint(usdc, stata, REDEEM_YIELD);
    const assets = await this.evm.previewRedeem(stata, SUPPLY_AMOUNT);
    await tron.sendToken(usdt, share, TRON_LEND_YIELD);
    const tronAssets = await tron.read(
      share,
      "previewRedeem(uint256)",
      numericAbiWord(mintedShares * SHARE_FACTOR),
    );
    const redeems = await this.settleRound(
      [sentOf(redeemsSent, "redeem")],
      [{ request: sentOf(redeemsSent, "tronRedeem") }],
    );
    const redeem = attestedOf(redeems.attested, "redeem");
    const tronRedeem = attestedOf(redeems.attested, "tronRedeem");
    if (assets <= SUPPLY_AMOUNT || redeem.decoded.assets !== assets) {
      throw new Error(`the redeem attested ${String(redeem.decoded.assets)}, expected ${assets}`);
    }
    if (
      tronAssets <= TRON_SUPPLY_AMOUNT ||
      tronRedeem.decoded.assets !== tronAssets ||
      calldataWord(tronRedeem.calldata, 0) !== mintedShares * SHARE_FACTOR ||
      (await tron.balanceOf(usdt, vaultTron)) - vaultBeforeRedeem.usdt !== tronAssets ||
      vaultBeforeRedeem.share - (await tron.balanceOf(share, vaultTron)) !==
        mintedShares * SHARE_FACTOR
    ) {
      throw new Error(
        `the Tron redeem attested ${String(tronRedeem.decoded.assets)}, expected ${tronAssets}`,
      );
    }
    await this.queueAndFlush([redeem, tronRedeem]);
    await this.vault.callTx.completeRedeem(
      hexToBytes(redeem.requestId),
      redeem.output,
      randomBytes(32),
    );
    await this.vault.callTx.completeTronRedeem(
      hexToBytes(tronRedeem.requestId),
      tronRedeem.output,
      randomBytes(32),
    );
    await this.removed(redeem);
    await this.removed(tronRedeem);
    usdcCoins += assets;
    usdtCoins += tronAssets;
    await this.expectBalance(usdc, usdcCoins);
    await this.expectBalance(stata, 0n);
    await this.expectBalance(usdtHex, usdtCoins, TargetChain.Tron);
    await this.expectBalance(shareHex, shareCoins, TargetChain.Tron);
    this.scenario(
      "redeem",
      "executed, assets above the supply minted",
      `executed, ${assets} minted`,
      startedAt("redeem"),
    );
    this.scenario(
      "tronRedeem",
      "executed, calldata q x 10^12, assets above the supply minted",
      `executed, calldata ${mintedShares * SHARE_FACTOR}, ${tronAssets} assets minted`,
      startedAt("tronRedeem"),
    );

    // Every coin of a Tron colour, the fee recipient's included, is backed by the vault's
    // Tron account at its factor; the shares also keep the supply's remainder.
    const feeCoins = {
      usdt: 4n * TRON_SUPPLY_FEE,
      share: 4n * TRON_REDEEM_FEE,
    };
    const backing = {
      underlyingVault: await tron.balanceOf(usdt, vaultTron),
      underlyingCoins: usdtCoins + feeCoins.usdt,
      shareVault: await tron.balanceOf(share, vaultTron),
      shareCoins: shareCoins + feeCoins.share,
    };
    if (
      backing.underlyingVault !== backing.underlyingCoins ||
      backing.shareVault !== backing.shareCoins * SHARE_FACTOR + remainder
    ) {
      throw new Error(
        `the vault's Tron account does not back its coins: ${JSON.stringify(backing, bigintJson)}`,
      );
    }

    const settled = await this.readLedger();
    const leftovers = Object.entries({
      inputRequestBuffer: settled.inputRequestBuffer.size(),
      outputRequestBuffer: settled.outputRequestBuffer.size(),
      inputAttestationBuffer: settled.inputAttestationBuffer.size(),
      outputAttestationBuffer: settled.outputAttestationBuffer.size(),
      evictionMap: settled.evictionMap.size(),
      depositArgsMap: settled.depositArgsMap.size(),
      approveArgsMap: settled.approveArgsMap.size(),
      withdrawArgsMap: settled.withdrawArgsMap.size(),
      supplyArgsMap: settled.supplyArgsMap.size(),
      redeemArgsMap: settled.redeemArgsMap.size(),
      tronDepositArgsMap: settled.tronDepositArgsMap.size(),
      tronWithdrawArgsMap: settled.tronWithdrawArgsMap.size(),
      tronApproveArgsMap: settled.tronApproveArgsMap.size(),
      tronSupplyArgsMap: settled.tronSupplyArgsMap.size(),
      tronRedeemArgsMap: settled.tronRedeemArgsMap.size(),
      ...Object.fromEntries(
        Object.values(REQUEST_MAPS).map(({ field }) => [field, settled[field].size()]),
      ),
    }).filter(([, size]) => size !== 0n);
    if (leftovers.length > 0) {
      throw new Error(`the vault kept ${JSON.stringify(leftovers, bigintJson)}`);
    }

    return {
      vaultAddress: this.vaultAddress,
      tronToken: gateHex,
      operations: this.operations,
      lastSeen: { before, afterEthereum, afterTron, ethereumFlushed, tronFlushed },
      crossChainRefusals: { tronCompleteOfEthereum, ethereumCompleteOfTron },
      unsentRefund: { lateSendRefusal: lateSendRefusals.join(" / "), waitedMs },
      recipient: {
        address: bytesToHex(recipient),
        before: Number(recipientBefore),
        after: Number(recipientAfter),
      },
      withdrawBinding: {
        binding: calldataWord(tronWithdraw.calldata, 2).toString(16).padStart(64, "0"),
        expectedBinding: bytesToHex(
          pureCircuits.ownershipCommitment(tronWithdrawStart.inIndex, this.userSecret),
        ),
      },
      tronLend: {
        underlying: usdtHex,
        shareToken: shareHex,
        shareFactor: String(SHARE_FACTOR),
        supply: {
          amount: String(TRON_SUPPLY_AMOUNT),
          calldataAmount: String(calldataWord(tronSupply.calldata, 0)),
          shares: String(supplied),
          minted: String(mintedShares),
          remainder: String(remainder),
          binding: calldataWord(tronSupply.calldata, 2).toString(16).padStart(64, "0"),
          expectedBinding: bytesToHex(
            pureCircuits.ownershipCommitment(tronSupplyStart.inIndex, this.userSecret),
          ),
        },
        redeem: {
          shares: String(mintedShares),
          calldataShares: String(calldataWord(tronRedeem.calldata, 0)),
          assets: String(tronAssets),
          binding: calldataWord(tronRedeem.calldata, 3).toString(16).padStart(64, "0"),
          expectedBinding: bytesToHex(
            pureCircuits.ownershipCommitment(tronRedeemStart.inIndex, this.userSecret),
          ),
        },
        shareDeposit: {
          amount: String(TRON_SHARE_DEPOSIT),
          calldataAmount: String(calldataWord(shareDeposit.calldata, 1)),
        },
        shareWithdraw: {
          amount: String(TRON_SHARE_WITHDRAW),
          calldataAmount: String(calldataWord(shareWithdraw.calldata, 1)),
          received: String(shareReceived),
          binding: calldataWord(shareWithdraw.calldata, 2).toString(16).padStart(64, "0"),
          expectedBinding: bytesToHex(
            pureCircuits.ownershipCommitment(shareWithdrawStart.inIndex, this.userSecret),
          ),
        },
        starvedSupply: {
          feeLimit: String(TRON_STARVED_FEE_LIMIT),
          broadcastRefusal,
        },
        backing: {
          underlyingVault: String(backing.underlyingVault),
          underlyingCoins: String(backing.underlyingCoins),
          shareVault: String(backing.shareVault),
          shareCoins: String(backing.shareCoins),
        },
      },
      scenarios: this.scenarios,
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
