// Simulator-level unit tests: the contract runs entirely in-process via
// @midnight-ntwrk/compact-runtime. No ledger, no network, no proving.

import {
  type CircuitContext,
  type CircuitResults,
  createCircuitContext,
  createConstructorContext,
  rawTokenType,
  sampleContractAddress,
} from "@midnight-ntwrk/compact-runtime";
// This tree's wasm ContractState class: see signetStateProvider for why the
// portal-linked signet module's state must round-trip through it.
import { ContractState } from "@midnightntwrk/onchain-runtime-v4";
import {
  asciiPadded,
  bytesToHex,
  calculateRequestId,
  decodeSignBidirectionalEventNotificationPayload,
  decodeSignBidirectionalNotification,
  decodeSignetLogEvents,
  evmAddressAbiWord,
  hexToBytes,
  MPC_FAILURE_OUTPUT,
  MPCDestination,
  MPCSignatureAlgorithm,
  numericAbiWord,
  pureCircuits as signetCircuits,
  readSignetRequestsLedgerFromState,
  type RequestId,
  requestIdBytes,
  requestIdHex,
  type RespondBidirectionalEvent,
  respondBidirectionalEventToCircuitInput,
  serializeRespondOutput,
  type SignBidirectionalEventLedgerMap,
  SignetEventName,
  signetFieldNodeByPath,
  toSignBidirectionalEventIndex,
  TxParamType,
} from "@sig-net/midnight";
import {
  calculateSignetAttestationDigest,
  ecdsaSignatureToMpcSignature,
  secp256k1PublicKeyOf,
  signAttestationDigest,
} from "@sig-net/midnight/testing";
import { describe, expect, it } from "vitest";

// The ERC20 transfer(address,uint256) selector: the TS mirror of the literal
// `Bytes [0xa9, 0x05, 0x9c, 0xbb]` hardcoded in erc20-vault.compact.
const ERC20_TRANSFER_SELECTOR = new Uint8Array([0xa9, 0x05, 0x9c, 0xbb]);

// The signet contract (callee) module, the same one the vault's generated code
// cross-contract-calls (via the compile-time src/managed/SignetSigner link
// into this npm package's managed output). The request circuits end in a call
// to its signBidirectional, so the simulator needs its state
// (see signetStateProvider) to execute that path.
import * as SignetSigner from "@sig-net/midnight-contract/managed/contract/index.js";

import {
  Contract,
  createVaultPrivateState,
  ledger,
  pureCircuits,
  VAULT_DEPOSIT_REQUESTS_PATH,
  VAULT_NONCE_PATH,
  VAULT_REQUESTS_PATH,
  type VaultPrivateState,
  witnesses,
} from "../src/index.ts";

// ---- Fixtures ----

// Dummy coin public key (32-byte hex). Required by the API, unused here.
const CPK = "0".repeat(64);

const bytes = (length: number, fill: number) => new Uint8Array(length).fill(fill);

// A `toHaveLength` assertion does not narrow the index read that follows it,
// so take the first element by iterating and fail naming what was missing.
const first = <T>(items: Iterable<T>, what: string): T => {
  for (const item of items) {
    return item;
  }
  throw new Error(`expected at least one ${what}`);
};

// The stdlib's shieldedBurnAddress() recipient: the all-zero coin public key.
// The burn-output assertions below are the lockstep check for this mirror.
const BURN_ADDRESS_BYTES = new Uint8Array(32);

/** The zswap local state a circuit run produced, failing when there is none. */
const zswapState = (context: CircuitContext<VaultPrivateState>) => {
  const state = context.callContext.currentZswapLocalState;
  if (!state) {
    throw new Error("expected zswap local state on the circuit context");
  }
  return state;
};

// Identity secrets for the simulated deployer/caller (same key: the deployer
// deposits in these tests) and for a stranger.
const SECRET_KEY = bytes(32, 7);
const OTHER_SECRET_KEY = bytes(32, 8);

// Commitments computed via the COMPILED circuit
const DEPLOYER_COMMITMENT = pureCircuits.userCommitment(SECRET_KEY);
const OTHER_COMMITMENT = pureCircuits.userCommitment(OTHER_SECRET_KEY);

// The "MPC" of these tests: its response key (secp256k1, derived per client
// contract from the contract address + the fixed path "midnight response
// key") is pinned by the one-shot initialise circuit right after deploy,
// exactly as a real deployment pins the off-chain-derived key (the key
// depends on the contract's own address, so it cannot be a constructor arg).
const MPC_RESPONSE_SECRET = bytes(32, 0x42);
const MPC_RESPONSE_KEY = secp256k1PublicKeyOf(MPC_RESPONSE_SECRET);

// The signet contract (callee) the vault seals + cross-contract-calls. A valid
// sample contract address so the runtime's address checks pass.
const SIGNET_ADDRESS = sampleContractAddress();
const SIGNET_CONTRACT_REF = {
  bytes: hexToBytes(SIGNET_ADDRESS),
};
const BLOCK_HASH = "0".repeat(64);

/**
 * A ContractStateProvider serving the signet contract's initial state to the
 * simulator's cross-contract call, which is how the request circuits reach
 * signBidirectionalEvent in-process (no node/indexer). Returns the state for
 * any address: the vault only calls the single sealed signet contract.
 *
 * The state is re-materialised through bytes: while `@sig-net/*` resolve to
 * the sibling checkout (portal wiring), the signet module runs on its OWN
 * copy of the wasm runtime, and the simulator's `instanceof ContractState`
 * checks demand THIS tree's class identity. Serialisation is
 * identity-neutral, so a byte round trip converts between the two. Harmless
 * (a no-op copy) under published single-tree installs.
 */
const signetStateProvider = async () => {
  const signet = new SignetSigner.Contract({});
  const { currentContractState } = await signet.initialState(
    createConstructorContext(undefined, CPK),
  );
  const state = ContractState.deserialize(currentContractState.serialize());
  return { getContractState: () => Promise.resolve(state) };
};

const VAULT_EVM = bytes(20, 0xee);
// The pinned Uniswap SwapRouter02 (initialise arg + swap `to`).
const ROUTER = bytes(20, 0x11);
const ERC20 = bytes(20, 0xaa);
// The pinned Aave USDC pair (initialise args): the underlying and its stataUSDC wrapper.
const STATA_UNDERLYING = bytes(20, 0xdd); // supply burns this colour, redeem mints it
const STATA_TOKEN = bytes(20, 0xcc); // supply/redeem `to`; supply mints this colour
const ZERO_ADDRESS = new Uint8Array(20);
const AMOUNT = 1_000_000n;
const UINT64_MAX = 18446744073709551615n;

// The EIP-155 chain id initialise() pins (Sepolia's).
const CHAIN_ID = 11155111n;

// The simulated vault's own contract address, fixed so tests can compute the
// token colors withdraw checks against kernel.self(). Doubles as the sender
// field of every event the vault records (kernel.self() again).
const VAULT_ADDRESS = sampleContractAddress();
const VAULT_ADDRESS_BYTES = hexToBytes(VAULT_ADDRESS);

// The contract-fixed MPC routing of every vault event (mirrors of the
// in-circuit constants; the round-trip tests below are the lockstep check for
// these values, including the escaped JSON schema literal at its EXACT
// contract-declared 34-byte width, never zero-padded).
const EXPECTED_SCHEMA = asciiPadded('[{"name":"success","type":"bool"}]', 34);
const EXPECTED_ROUTING = {
  algo: MPCSignatureAlgorithm.ecdsa,
  dest: MPCDestination.unused,
  params: new Uint8Array(64),
  caip2Id: signetCircuits.ethereumCaip2Id(),
  outputDeserializationSchema: EXPECTED_SCHEMA,
  respondSerializationSchema: EXPECTED_SCHEMA,
};

/**
 * The `startDeposit` circuit's flat arguments, in circuit order. The compact
 * compiler inlines the `DepositRequest` struct type anonymously into the
 * generated circuit signature, and this interface's `deposit` member matches
 * that anonymous type structurally.
 * There is no path argument any more: the derivation path IS the caller's
 * identity commitment, recomputed in-circuit from the secret-key witness.
 */
interface DepositCallArgs {
  evmNonce: bigint;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  keyVersion: bigint;
  deposit: { erc20Address: Uint8Array; amount: bigint };
}

/**
 * Known-good deposit call args, the base every test varies from.
 * Shared across tests: NEVER mutate; build a variation as an explicit spread
 * of this base with the delta inline (see {@link DEPOSIT_REJECTION_CASES}).
 */
const VALID_DEPOSIT: DepositCallArgs = {
  evmNonce: 0n,
  gasLimit: 100000n,
  maxFeePerGas: 30000000000n,
  maxPriorityFeePerGas: 2000000000n,
  keyVersion: 1n,
  deposit: { erc20Address: ERC20, amount: AMOUNT },
};

// ---- Harness ----

const deployContract = async (deployerCommitment: Uint8Array = DEPLOYER_COMMITMENT) => {
  const contract = new Contract<VaultPrivateState>(witnesses);
  const { currentContractState, currentPrivateState } = await contract.initialState(
    createConstructorContext<VaultPrivateState>(createVaultPrivateState(SECRET_KEY), CPK),
    deployerCommitment,
    SIGNET_CONTRACT_REF,
  );
  const ctx = createCircuitContext(
    "startDeposit",
    VAULT_ADDRESS,
    CPK,
    currentContractState,
    currentPrivateState,
    await signetStateProvider(),
    undefined,
    undefined,
    undefined,
    BLOCK_HASH,
  );
  return { contract, ctx };
};

/**
 * Re-enter a threaded contract state as a DIFFERENT caller: same public
 * state, but the private state (the callerSecretKey witness) is a stranger's
 * ({@link OTHER_SECRET_KEY}).
 */
const strangerContext = async (
  circuitId: string,
  ctx: Parameters<Contract<VaultPrivateState>["circuits"]["startDeposit"]>[0],
) =>
  createCircuitContext(
    circuitId,
    VAULT_ADDRESS,
    CPK,
    ctx.callContext.currentQueryContext.state,
    createVaultPrivateState(OTHER_SECRET_KEY),
    await signetStateProvider(),
    undefined,
    undefined,
    undefined,
    BLOCK_HASH,
  );

/**
 * Deploy + initialise(VAULT_EVM, CHAIN_ID, MPC_RESPONSE_KEY) as
 * the deployer: the ready-to-use vault, with the MPC response key stored.
 */
const deployInitialised = async () => {
  const { contract, ctx } = await deployContract();
  const next = (
    await contract.circuits.initialise(
      ctx,
      VAULT_EVM,
      ROUTER,
      STATA_UNDERLYING,
      STATA_TOKEN,
      CHAIN_ID,
      MPC_RESPONSE_KEY,
    )
  ).context;
  return { contract, ctx: next };
};

/** Call deposit with its flat args spread in circuit order. */
const deposit = (
  contract: Contract<VaultPrivateState>,
  ctx: Parameters<Contract<VaultPrivateState>["circuits"]["startDeposit"]>[0],
  args: DepositCallArgs,
) =>
  contract.circuits.startDeposit(
    ctx,
    args.evmNonce,
    args.gasLimit,
    args.maxFeePerGas,
    args.maxPriorityFeePerGas,
    args.keyVersion,
    args.deposit,
  );

// ---- Tests ----

describe("erc20-vault ledger shape", () => {
  it("signBidirectionalEventMap parses into the shared signet-midnight types", async () => {
    const { ctx } = await deployContract();

    // The assignment is the real assertion: the generated ledger type must
    // stay structurally identical to the shared library's named types.
    const ledgerMap: SignBidirectionalEventLedgerMap = ledger(
      ctx.callContext.currentQueryContext.state,
    ).signBidirectionalEventMap;

    expect(ledgerMap.isEmpty()).toBe(true);
    expect(toSignBidirectionalEventIndex(ledgerMap).size).toBe(0);
  });

  it("MPC-style: finds the event map in RAW state by ledger-tree path, no ledger()", async () => {
    const { ctx } = await deployContract();

    const rawState = ctx.callContext.currentQueryContext.state;
    const node = signetFieldNodeByPath(rawState, VAULT_REQUESTS_PATH);
    expect(node.type()).toBe("map");

    const { nonce, requestsIndex } = readSignetRequestsLedgerFromState(
      rawState,
      VAULT_REQUESTS_PATH,
      VAULT_NONCE_PATH,
    );
    const typedIndex = toSignBidirectionalEventIndex(
      ledger(ctx.callContext.currentQueryContext.state).signBidirectionalEventMap,
    );
    expect(requestsIndex).toEqual(typedIndex);
    expect(requestsIndex.size).toBe(0);
    expect(nonce).toBe(0n);
  });
});

describe("userCommitment", () => {
  it("check 32-byte commitments computed off-chain via the compiled circuit", () => {
    expect(DEPLOYER_COMMITMENT).toHaveLength(32);
    expect(DEPLOYER_COMMITMENT).not.toEqual(new Uint8Array(32));
    expect(DEPLOYER_COMMITMENT).not.toEqual(OTHER_COMMITMENT);
  });
});

describe("refundCommitment", () => {
  it("is domain-separated from userCommitment and unique per secret AND per request id", () => {
    const requestIdA = bytes(32, 0x01);
    const requestIdB = bytes(32, 0x02);
    const commitment = pureCircuits.refundCommitment(SECRET_KEY, requestIdA);
    expect(commitment).toHaveLength(32);
    // Never the deposit-identity commitment: THAT one is public on the ledger
    // as the deposit's derivation path, so equality would link withdraw to
    // deposit.
    expect(commitment).not.toEqual(pureCircuits.userCommitment(SECRET_KEY));
    // Bound to the request id: two withdrawals by the same secret differ.
    expect(commitment).not.toEqual(pureCircuits.refundCommitment(SECRET_KEY, requestIdB));
    // And bound to the secret: another identity's commitment differs.
    expect(commitment).not.toEqual(pureCircuits.refundCommitment(OTHER_SECRET_KEY, requestIdA));
  });
});

describe("ABI words (shared library circuits)", () => {
  it("TS mirrors match the compiled circuits byte for byte", () => {
    // Words are ABI-ready (big-endian, broadcast form); the library's TS
    // mirrors and its compiled circuits must emit identical bytes. The vault
    // stores exactly these words (see the deposit/withdraw record tests).
    expect(evmAddressAbiWord(VAULT_EVM)).toEqual(signetCircuits.evmAddressAbiWord(VAULT_EVM));
    expect(numericAbiWord(AMOUNT)).toEqual(signetCircuits.numericAbiWord(AMOUNT));
    expect(signetCircuits.abiWordToUint128(numericAbiWord(AMOUNT))).toBe(AMOUNT);
  });
});

describe("initialise", () => {
  it("is deployer-gated", async () => {
    // Deployed with a stranger's commitment; our caller key can't initialise.
    const { contract, ctx } = await deployContract(OTHER_COMMITMENT);
    await expect(
      contract.circuits.initialise(
        ctx,
        VAULT_EVM,
        ROUTER,
        STATA_UNDERLYING,
        STATA_TOKEN,
        CHAIN_ID,
        MPC_RESPONSE_KEY,
      ),
    ).rejects.toThrow(/Not the deployer/);
  });

  it("is one-shot", async () => {
    const { contract, ctx } = await deployInitialised();
    await expect(
      contract.circuits.initialise(
        ctx,
        VAULT_EVM,
        ROUTER,
        STATA_UNDERLYING,
        STATA_TOKEN,
        CHAIN_ID,
        MPC_RESPONSE_KEY,
      ),
    ).rejects.toThrow(/Already initialised/);
  });

  it("rejects a zero chain id", async () => {
    const { contract, ctx } = await deployContract();
    await expect(
      contract.circuits.initialise(
        ctx,
        VAULT_EVM,
        ROUTER,
        STATA_UNDERLYING,
        STATA_TOKEN,
        0n,
        MPC_RESPONSE_KEY,
      ),
    ).rejects.toThrow(/Chain ID must be positive/);
  });

  it("stores the vault EVM address, the chain id and the MPC response key", async () => {
    const { ctx } = await deployInitialised();
    const state = ledger(ctx.callContext.currentQueryContext.state);
    expect(state.initialised).toBe(1n);
    expect(state.vaultEvmAddress).toEqual(VAULT_EVM);
    expect(state.uniswapRouter).toEqual(ROUTER);
    expect(state.evmChainId).toBe(CHAIN_ID);
    expect(state.mpcResponseKey).toEqual(MPC_RESPONSE_KEY);
  });
});

describe("deposit round-trip", () => {
  it("stores a fully contract-composed event readable identically via ledger(), the shared parser, and the RAW reader", async () => {
    const { contract, ctx } = await deployInitialised();

    const { context: next } = await deposit(contract, ctx, VALID_DEPOSIT);
    const state = next.callContext.currentQueryContext.state;

    // Read 1: generated ledger().
    const typedIndex = toSignBidirectionalEventIndex(ledger(state).depositEventMap);
    // Read 2: MPC-style raw read, no compiled contract involved.
    const rawLedger = readSignetRequestsLedgerFromState(
      state,
      VAULT_DEPOSIT_REQUESTS_PATH,
      VAULT_NONCE_PATH,
    );

    expect(typedIndex.size).toBe(1);
    expect(rawLedger.requestsIndex).toEqual(typedIndex);
    // The raw counter read matches the generated one.
    expect(rawLedger.nonce).toBe(ledger(state).signetRequestNonce);

    const [idHex, record] = first(typedIndex.entries(), "indexed signBidirectional request");

    // The cross-contract call's observable effect: the signet contract
    // emitted the notification event, its payload declaring the stored
    // event's id and naming THIS vault and the depositEventMap (decoded
    // through the shared library's decoders, the same read the MPC's
    // discovery feed performs).
    const notificationEvents = decodeSignetLogEvents(next.events, SIGNET_ADDRESS);
    expect(notificationEvents).toHaveLength(1);
    const notificationEvent = first(notificationEvents, "signet notification event");
    expect(notificationEvent.name).toBe(SignetEventName.SignBidirectionalEvent);
    const notificationPost = decodeSignBidirectionalEventNotificationPayload(
      notificationEvent.payload,
    );
    // The declared id IS the stored map key: the MPC looks it up directly.
    expect(requestIdHex(notificationPost.requestId)).toBe(idHex);
    expect(decodeSignBidirectionalNotification(notificationPost.event)).toEqual({
      version: 1,
      callerAddress: bytesToHex(VAULT_ADDRESS_BYTES),
      requestsPath: [1, 3],
    });

    // The contract-composed envelope: the deposit's token on the
    // initialise-pinned chain, no ETH value, the caller's nonce + gas args.
    const { calldata, ...envelope } = record.txParams;
    expect(envelope).toEqual({
      to: ERC20,
      chainId: CHAIN_ID,
      nonce: VALID_DEPOSIT.evmNonce,
      gasLimit: VALID_DEPOSIT.gasLimit,
      maxFeePerGas: VALID_DEPOSIT.maxFeePerGas,
      maxPriorityFeePerGas: VALID_DEPOSIT.maxPriorityFeePerGas,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
    });

    // The event commits to its own sender (kernel.self()) and carries the
    // caller's identity commitment as its 32-byte derivation path. The
    // contract-fixed routing matches the TS expectations: the LOCKSTEP CHECK
    // for the in-circuit constants (including the escaped JSON schema
    // literal at its exact 34-byte width).
    expect(record.sender).toEqual({ bytes: VAULT_ADDRESS_BYTES });
    expect(record.path).toEqual(DEPLOYER_COMMITMENT);
    expect(record.caip2Id).toEqual(EXPECTED_ROUTING.caip2Id);
    expect(record.keyVersion).toBe(VALID_DEPOSIT.keyVersion);
    expect(record.algo).toBe(EXPECTED_ROUTING.algo);
    expect(record.dest).toBe(EXPECTED_ROUTING.dest);
    expect(record.params).toEqual(EXPECTED_ROUTING.params);
    expect(record.txParamType).toBe(TxParamType.evmType2);
    expect(record.outputDeserializationSchema).toEqual(
      EXPECTED_ROUTING.outputDeserializationSchema,
    );
    expect(record.respondSerializationSchema).toEqual(EXPECTED_ROUTING.respondSerializationSchema);
    expect(record.requestNonce).toBe(0n);

    // Contract-built calldata: transfer(vaultEvmAddress, amount) as ABI-ready
    // big-endian words, stored exactly as broadcast.
    expect(calldata.is_some).toBe(true);
    expect(calldata.value.selector).toEqual(ERC20_TRANSFER_SELECTOR);
    expect(calldata.value.noWords).toBe(2n);
    expect(calldata.value.words).toHaveLength(2);
    expect(calldata.value.words[0]).toEqual(evmAddressAbiWord(VAULT_EVM));
    expect(calldata.value.words[1]).toEqual(numericAbiWord(AMOUNT));

    // The map key IS the record's transientHash digest, recomputed off-chain
    // with the library's TS twin of the request-id circuit. This assertion is
    // the lockstep check the twin's deviation note relies on: the id computed
    // in TS must equal the key the REAL compiled contract minted in-circuit.
    expect(idHex).toBe(requestIdHex(calculateRequestId(record)));

    // The depositor's settle view is pinned under the request id: the identity
    // commitment completeDeposit gates on plus the typed token + amount it
    // mints, so settling never decodes an ABI word.
    expect(ledger(state).depositSettleViews.member(requestIdBytes(idHex))).toBe(true);
    expect(ledger(state).depositSettleViews.lookup(requestIdBytes(idHex))).toEqual({
      commitment: DEPLOYER_COMMITMENT,
      erc20: ERC20,
      amount: AMOUNT,
    });

    // Nonce bumped for the next request.
    expect(ledger(state).signetRequestNonce).toBe(1n);
  });
});

/** One row of the deposit rejection table: full inputs to expected error. */
interface DepositRejectionCase {
  /** Test name, completing the sentence "rejects <name>". */
  name: string;
  /** Complete call args passed to the circuit. */
  args: DepositCallArgs;
  /** Error the circuit must throw. */
  throws: RegExp;
}

const DEPOSIT_REJECTION_CASES: DepositRejectionCase[] = [
  {
    name: "a zero ERC20 address",
    args: { ...VALID_DEPOSIT, deposit: { erc20Address: ZERO_ADDRESS, amount: AMOUNT } },
    throws: /ERC20 address cannot be zero/,
  },
  {
    name: "a zero amount",
    args: { ...VALID_DEPOSIT, deposit: { erc20Address: ERC20, amount: 0n } },
    throws: /Amount must be positive/,
  },
  {
    name: "an amount above Uint<64> max (unclaimable)",
    args: { ...VALID_DEPOSIT, deposit: { erc20Address: ERC20, amount: UINT64_MAX + 1n } },
    throws: /Amount exceeds Uint<64> max/,
  },
  {
    name: "a zero gas limit",
    args: { ...VALID_DEPOSIT, gasLimit: 0n },
    throws: /Gas limit must be positive/,
  },
  {
    name: "the legacy key version 0",
    args: { ...VALID_DEPOSIT, keyVersion: 0n },
    throws: /keyVersion must be >= 1/,
  },
];

describe("deposit validation", () => {
  it.each(DEPOSIT_REJECTION_CASES)("rejects $name", async ({ args, throws }) => {
    const { contract, ctx } = await deployInitialised();
    await expect(deposit(contract, ctx, args)).rejects.toThrow(throws);
  });

  it("rejects before initialise", async () => {
    const { contract, ctx } = await deployContract();
    await expect(deposit(contract, ctx, VALID_DEPOSIT)).rejects.toThrow(/Not initialised/);
  });

  it("identical deposits get DISTINCT ids: requestNonce differentiates them", async () => {
    // The dedup assert (!member) is a belt-and-braces invariant: it cannot
    // trip in the normal flow, as the nonce is part of the hashed record and
    // an identical resubmission is therefore a NEW request. Document that here.
    const { contract, ctx } = await deployInitialised();

    const afterFirst = (await deposit(contract, ctx, VALID_DEPOSIT)).context;
    const afterSecond = (await deposit(contract, afterFirst, VALID_DEPOSIT)).context;

    const index = toSignBidirectionalEventIndex(
      ledger(afterSecond.callContext.currentQueryContext.state).depositEventMap,
    );
    expect(index.size).toBe(2);
    const nonces = [...index.values()].map((r) => r.requestNonce).sort();
    expect(nonces).toEqual([0n, 1n]);
  });

  it("two identities depositing identical requests get DISTINCT ids: the path differentiates them", async () => {
    // The derivation path (the caller's commitment) is part of the hashed
    // record too, so the same deposit by two different identities can never
    // collide even at the same nonce.
    const { contract, ctx } = await deployInitialised();
    const afterFirst = (await deposit(contract, ctx, VALID_DEPOSIT)).context;
    const stranger = await strangerContext("startDeposit", afterFirst);
    const afterSecond = (await deposit(contract, stranger, VALID_DEPOSIT)).context;

    const index = toSignBidirectionalEventIndex(
      ledger(afterSecond.callContext.currentQueryContext.state).depositEventMap,
    );
    expect(index.size).toBe(2);
    const paths = [...index.values()].map((r) => r.path);
    expect(paths).toContainEqual(DEPLOYER_COMMITMENT);
    expect(paths).toContainEqual(OTHER_COMMITMENT);
  });
});

// ---- Withdraw fixtures ----

// Where the vault sends the ERC20 on withdraw.
const DEST_EVM = bytes(20, 0xdd);

// The vault token color for ERC20 at the simulated contract address,
// computed exactly as a wallet would: the compiled domain-separator circuit
// plus the runtime's rawTokenType (the off-chain twin of the in-circuit
// `tokenType(domainSep, kernel.self())`).
const VAULT_TOKEN_COLOR = hexToBytes(
  rawTokenType(pureCircuits.vaultTokenDomainSeparator(ERC20), VAULT_ADDRESS),
);

/** A surrendered vault coin: fixed nonce, vault-token color, given value. */
const vaultCoin = (value: bigint, color: Uint8Array = VAULT_TOKEN_COLOR) => ({
  nonce: bytes(32, 0x0c),
  color,
  value,
});

/**
 * The `startWithdraw` circuit's flat arguments, in circuit order. The compact
 * compiler inlines the `WithdrawRequest` struct type anonymously into the
 * generated circuit signature, and this interface's `withdraw` member matches
 * that anonymous type structurally.
 */
interface WithdrawCallArgs {
  evmNonce: bigint;
  keyVersion: bigint;
  withdraw: { erc20Address: Uint8Array; amount: bigint; destEvmAddress: Uint8Array };
  coin: ReturnType<typeof vaultCoin>;
}

/**
 * Known-good withdraw call args, the base every test varies from.
 * Shared across tests: NEVER mutate; build a variation as an explicit spread.
 */
const VALID_WITHDRAW: WithdrawCallArgs = {
  evmNonce: 0n,
  keyVersion: 1n,
  withdraw: { erc20Address: ERC20, amount: AMOUNT, destEvmAddress: DEST_EVM },
  coin: vaultCoin(AMOUNT),
};

/** Call withdraw with its flat args spread in circuit order. */
const withdraw = (
  contract: Contract<VaultPrivateState>,
  ctx: Parameters<Contract<VaultPrivateState>["circuits"]["startWithdraw"]>[0],
  args: WithdrawCallArgs,
) => contract.circuits.startWithdraw(ctx, args.evmNonce, args.keyVersion, args.withdraw, args.coin);

// ---- Withdraw tests ----

describe("withdraw round-trip", () => {
  it("burns the coin and stores a vault-path event with a contract-fixed envelope", async () => {
    const { contract, ctx } = await deployInitialised();

    const { context: next } = await withdraw(contract, ctx, VALID_WITHDRAW);
    const state = next.callContext.currentQueryContext.state;

    const index = toSignBidirectionalEventIndex(ledger(state).signBidirectionalEventMap);
    expect(index.size).toBe(1);
    const [idHex, record] = first(index.entries(), "indexed signBidirectional request");

    // The cross-contract call's observable effect: the signet contract
    // emitted the notification event declaring the stored event's id and
    // naming this vault's signBidirectionalEventMap.
    const notificationEvent = first(
      decodeSignetLogEvents(next.events, SIGNET_ADDRESS),
      "signet notification event",
    );
    expect(notificationEvent.name).toBe(SignetEventName.SignBidirectionalEvent);
    const notificationPost = decodeSignBidirectionalEventNotificationPayload(
      notificationEvent.payload,
    );
    // The declared id IS the stored map key: the MPC looks it up directly.
    expect(requestIdHex(notificationPost.requestId)).toBe(idHex);
    expect(decodeSignBidirectionalNotification(notificationPost.event)).toEqual({
      version: 1,
      callerAddress: bytesToHex(VAULT_ADDRESS_BYTES),
      requestsPath: [0, 0],
    });

    // The derivation path is the contract-fixed 32-byte literal "vault": the
    // MPC signs with the VAULT's derived EVM account, not the caller's. The
    // sender is the vault contract itself (kernel.self()).
    expect(record.sender).toEqual({ bytes: VAULT_ADDRESS_BYTES });
    expect(record.path).toEqual(asciiPadded("vault", 32));

    // The envelope is contract-composed end to end: the withdraw's token on
    // the initialise-pinned chain, the caller's account nonce, and the
    // CONTRACT-FIXED gas envelope. The gas literals here are the lockstep
    // check for any off-chain code that rebuilds this record (the example's
    // withdraw flow ERC20_TRANSFER_* constants).
    const { calldata, ...envelope } = record.txParams;
    expect(envelope).toEqual({
      to: ERC20,
      chainId: CHAIN_ID,
      nonce: VALID_WITHDRAW.evmNonce,
      gasLimit: 100_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
    });

    // Contract-fixed routing, same constants as deposits.
    expect(record.caip2Id).toEqual(EXPECTED_ROUTING.caip2Id);
    expect(record.keyVersion).toBe(VALID_WITHDRAW.keyVersion);
    expect(record.algo).toBe(EXPECTED_ROUTING.algo);
    expect(record.dest).toBe(EXPECTED_ROUTING.dest);
    expect(record.params).toEqual(EXPECTED_ROUTING.params);
    expect(record.txParamType).toBe(TxParamType.evmType2);
    expect(record.outputDeserializationSchema).toEqual(
      EXPECTED_ROUTING.outputDeserializationSchema,
    );
    expect(record.respondSerializationSchema).toEqual(EXPECTED_ROUTING.respondSerializationSchema);
    expect(record.requestNonce).toBe(0n);

    // Contract-built calldata: transfer(destEvmAddress, amount) as ABI-ready
    // big-endian words, stored exactly as broadcast.
    expect(calldata.is_some).toBe(true);
    expect(calldata.value.selector).toEqual(ERC20_TRANSFER_SELECTOR);
    expect(calldata.value.noWords).toBe(2n);
    expect(calldata.value.words[0]).toEqual(evmAddressAbiWord(DEST_EVM));
    expect(calldata.value.words[1]).toEqual(numericAbiWord(AMOUNT));

    // TS-twin lockstep: the ledger map key is the id the library recomputes.
    expect(idHex).toBe(requestIdHex(calculateRequestId(record)));

    // The withdrawer's settle view is pinned under the request id: the refund
    // commitment (recomputed off-chain here via the compiled circuit,
    // domain-separated from userCommitment and bound to THIS request id) plus
    // the typed token + amount settle circuits read back; nonce bumped.
    expect(ledger(state).withdrawSettleViews.member(requestIdBytes(idHex))).toBe(true);
    expect(ledger(state).withdrawSettleViews.lookup(requestIdBytes(idHex))).toEqual({
      commitment: pureCircuits.refundCommitment(SECRET_KEY, requestIdBytes(idHex)),
      erc20: ERC20,
      amount: AMOUNT,
    });
    expect(ledger(state).signetRequestNonce).toBe(1n);

    // The burn, observable in the zswap local state: the coin is received (a
    // contract-owned output) and spent as the call's input, and the burn
    // output pays its full value to the shielded burn address. The receive
    // output's coin info must equal the spent coin's exactly: that identity is
    // what lets the transaction builder pair the two into a same-transaction
    // transient instead of a contract coin-tree spend.
    const zswap = zswapState(next);

    // check inputs, expect 1 input:
    // - coin for the amount being withdrawn
    expect(zswap.inputs).toHaveLength(1);
    const consumed = first(zswap.inputs, "consumed coin");
    expect(consumed.color).toEqual(VAULT_TOKEN_COLOR);
    expect(consumed.value).toBe(AMOUNT);

    // check outputs, expect 2 ouputs:
    // - received coin to the contract address
    // - burned coin to the burn address
    expect(zswap.outputs).toHaveLength(2);

    // received coin to the contract address
    const received = first(
      zswap.outputs.filter((output) => !output.recipient.is_left),
      "contract-owned receive output",
    );
    expect(received.recipient.right.bytes).toEqual(VAULT_ADDRESS_BYTES);
    expect(received.coinInfo).toEqual({
      nonce: consumed.nonce,
      color: consumed.color,
      value: consumed.value,
    });

    // burned coin to the burn address
    const burnOutput = first(
      zswap.outputs.filter((output) => output.recipient.is_left),
      "burn output",
    );
    expect(burnOutput.coinInfo.color).toEqual(VAULT_TOKEN_COLOR);
    expect(burnOutput.coinInfo.value).toBe(AMOUNT);
    expect(burnOutput.recipient.left.bytes).toEqual(BURN_ADDRESS_BYTES);
  });

  it("concurrent withdrawals across DIFFERENT ERC20 colors both land", async () => {
    // No shared escrow slot: each withdrawal only touches its own request-id
    // keyed entries, so coins of different colors surrendered back-to-back
    // must both record.
    const { contract, ctx } = await deployInitialised();
    const otherErc20 = bytes(20, 0xab);
    const otherColor = hexToBytes(
      rawTokenType(pureCircuits.vaultTokenDomainSeparator(otherErc20), VAULT_ADDRESS),
    );

    const afterFirst = (await withdraw(contract, ctx, VALID_WITHDRAW)).context;
    const afterSecond = (
      await withdraw(contract, afterFirst, {
        ...VALID_WITHDRAW,
        withdraw: { erc20Address: otherErc20, amount: AMOUNT, destEvmAddress: DEST_EVM },
        coin: vaultCoin(AMOUNT, otherColor),
      })
    ).context;

    const state = afterSecond.callContext.currentQueryContext.state;
    const index = toSignBidirectionalEventIndex(ledger(state).signBidirectionalEventMap);
    expect(index.size).toBe(2);
    expect(ledger(state).withdrawSettleViews.size()).toBe(2n);
  });
});

/** One row of the withdraw rejection table: full inputs to expected error. */
interface WithdrawRejectionCase {
  /** Test name, completing the sentence "rejects <name>". */
  name: string;
  /** Complete call args passed to the circuit. */
  args: WithdrawCallArgs;
  /** Error the circuit must throw. */
  throws: RegExp;
}

const WITHDRAW_REJECTION_CASES: WithdrawRejectionCase[] = [
  {
    name: "a zero ERC20 address",
    args: {
      ...VALID_WITHDRAW,
      withdraw: { erc20Address: ZERO_ADDRESS, amount: AMOUNT, destEvmAddress: DEST_EVM },
    },
    throws: /ERC20 address cannot be zero/,
  },
  {
    name: "a zero amount",
    args: {
      ...VALID_WITHDRAW,
      withdraw: { erc20Address: ERC20, amount: 0n, destEvmAddress: DEST_EVM },
      coin: vaultCoin(0n),
    },
    throws: /Amount must be positive/,
  },
  {
    name: "an amount above Uint<64> max (unrefundable)",
    args: {
      ...VALID_WITHDRAW,
      withdraw: { erc20Address: ERC20, amount: UINT64_MAX + 1n, destEvmAddress: DEST_EVM },
      coin: vaultCoin(UINT64_MAX + 1n),
    },
    throws: /Amount exceeds Uint<64> max/,
  },
  {
    name: "the legacy key version 0",
    args: { ...VALID_WITHDRAW, keyVersion: 0n },
    throws: /keyVersion must be >= 1/,
  },
  {
    name: "a coin that is not the vault token for this ERC20",
    args: { ...VALID_WITHDRAW, coin: vaultCoin(AMOUNT, bytes(32, 0x99)) },
    throws: /Coin is not the vault token for this ERC20/,
  },
  {
    name: "a coin whose value differs from the withdraw amount",
    args: { ...VALID_WITHDRAW, coin: vaultCoin(AMOUNT - 1n) },
    throws: /Coin value must equal the withdraw amount/,
  },
];

describe("withdraw validation", () => {
  it.each(WITHDRAW_REJECTION_CASES)("rejects $name", async ({ args, throws }) => {
    const { contract, ctx } = await deployInitialised();
    await expect(withdraw(contract, ctx, args)).rejects.toThrow(throws);
  });

  it("rejects before initialise", async () => {
    const { contract, ctx } = await deployContract();
    await expect(withdraw(contract, ctx, VALID_WITHDRAW)).rejects.toThrow(/Not initialised/);
  });
});

// ---- Response fixtures (shared by every settle and refund suite) ----

// An MPC response secret OTHER than the one initialise pinned the key of.
const IMPOSTER_SECRET = bytes(32, 0x43);

// The caller-chosen mint nonce every settle and refund circuit takes. In production the
// client draws it fresh from a CSPRNG per call (that randomness is the
// unlinkability guarantee); the circuit only threads it through, so a fixed
// value is fine for these deterministic simulator tests.
const MINT_NONCE = bytes(32, 0x2e);
// completeSwap mints two coins, each under its own caller-supplied random nonce.
const CHANGE_NONCE = bytes(32, 0x3f);

// The vault's respond schema, read from the COMPILED circuit (the contract's
// own declaration), so the fixtures below run through the same ABI-to-compact
// pipeline the real client uses: schema -> descriptor -> midnight-serde
// compactSerialize. Nothing here hand-packs bytes.
const VAULT_RESPONSE_SCHEMA = pureCircuits.vaultResponseSchema();

// A successful remote execution: the packed bool result at its exact
// unpadded width, one 0x01 byte (the circuits take it as Bytes<1>).
const OUTPUT_SUCCESS = serializeRespondOutput(VAULT_RESPONSE_SCHEMA, { success: true });

// An EXECUTED transfer that returned false: one 0x00 byte. Settles through
// completeWithdraw's refund branch.
const OUTPUT_FALSE = serializeRespondOutput(VAULT_RESPONSE_SCHEMA, { success: false });

// A NEVER-EXECUTED transfer/swap (reverted or replaced): the protocol's fixed
// 5-byte failure output. Settles through the per-kind refund circuits, whose
// output argument is Bytes<5>.
const OUTPUT_REVERTED = MPC_FAILURE_OUTPUT;

/**
 * Sign a REAL RespondBidirectionalEvent for (requestId, serializedOutput)
 * with `secretKey`: the digest comes from the library's sanctioned TS twin
 * (pinned byte-for-byte against the compiled oracles in signet-midnight's
 * own tests), exactly like the MPC. The wire event carries ONLY the
 * stored-form signature (big-endian SEC1, bigR as a full point), and it is
 * returned flipped to verifyRespondBidirectionalEvent's circuit-input form,
 * which is what a client hands to the settle circuits: the digest is
 * recomputed by whoever verifies, and the output travels as a separate
 * circuit argument.
 */
const respond = (
  secretKey: Uint8Array,
  requestId: Uint8Array,
  serializedOutput: Uint8Array,
): RespondBidirectionalEvent =>
  respondBidirectionalEventToCircuitInput({
    signature: ecdsaSignatureToMpcSignature(
      signAttestationDigest(
        calculateSignetAttestationDigest(requestId, serializedOutput),
        secretKey,
      ),
    ),
  });

// ---- Complete-withdraw fixtures ----

/**
 * Deploy + initialise + withdraw(VALID_WITHDRAW): the arrange step of
 * every complete-withdraw test. Returns the pending withdrawal's request id
 * (the single ledger map key) alongside the threaded context.
 */
const withdrawRequested = async () => {
  const { contract, ctx } = await deployInitialised();
  const next = (await withdraw(contract, ctx, VALID_WITHDRAW)).context;
  const index = toSignBidirectionalEventIndex(
    ledger(next.callContext.currentQueryContext.state).signBidirectionalEventMap,
  );
  const idHex = first(index.keys(), "signBidirectional request id");
  return { contract, ctx: next, requestId: requestIdBytes(idHex) };
};

// ---- Complete-withdraw tests ----

describe("completeWithdraw settle", () => {
  it("success response finalizes: request and refund marker both consumed", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();

    const next = (
      await contract.circuits.completeWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      )
    ).context;

    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.signBidirectionalEventMap.isEmpty()).toBe(true);
    expect(state.withdrawSettleViews.isEmpty()).toBe(true);
  });

  it("success settle is permissionless: a STRANGER finalizes (cleanup mints nothing)", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();

    const next = (
      await contract.circuits.completeWithdraw(
        await strangerContext("completeWithdraw", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      )
    ).context;

    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.signBidirectionalEventMap.isEmpty()).toBe(true);
    expect(state.withdrawSettleViews.isEmpty()).toBe(true);
  });

  it("false-return response: the WITHDRAWER re-mints the surrendered value and consumes the withdrawal", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();

    // The refund branch runs mintShieldedToken in-circuit: the call
    // resolving proves the mint executed, and the ledger cleanup is the same
    // as the success branch (the mint itself is shielded, not ledger state).
    // The caller's private state holds SECRET_KEY, the secret behind the
    // pinned refund commitment, so the "Not the withdrawer" gate passes.
    const next = (
      await contract.circuits.completeWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_FALSE),
        OUTPUT_FALSE,
        MINT_NONCE,
      )
    ).context;

    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.signBidirectionalEventMap.isEmpty()).toBe(true);
    expect(state.withdrawSettleViews.isEmpty()).toBe(true);
  });

  it("false-return response: a caller other than the withdrawer cannot take the refund", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();

    // The refund mints to the CALLER's own key, so the circuit demands proof
    // of the secret behind the commitment pinned at withdraw time; a
    // stranger's callerSecretKey witness recomputes a different commitment.
    await expect(
      contract.circuits.completeWithdraw(
        await strangerContext("completeWithdraw", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_FALSE),
        OUTPUT_FALSE,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the withdrawer/);
  });

  it("rejects a response signed by a key other than the stored MPC response key", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    await expect(
      contract.circuits.completeWithdraw(
        ctx,
        requestId,
        respond(IMPOSTER_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("rejects presented output bytes that differ from what was signed", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    // Signed over the FALSE result, presented as a success byte: the digest
    // recomputed in-circuit is not the one the signature covers. This is the
    // attack the signature-only event must stop: settling a failed transfer
    // as a success.
    await expect(
      contract.circuits.completeWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_FALSE),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("rejects a genuine response presented under a different request id", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    // Signed for some OTHER id: the digest binds the request id, so the
    // signature cannot be replayed onto this pending withdrawal.
    const otherId = bytes(32, 0xab);
    await expect(
      contract.circuits.completeWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, otherId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("rejects a genuinely signed id that has no pending withdrawal", async () => {
    const { contract, ctx } = await withdrawRequested();
    const unknownId = bytes(32, 0xab);
    await expect(
      contract.circuits.completeWithdraw(
        ctx,
        unknownId,
        respond(MPC_RESPONSE_SECRET, unknownId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Withdrawal not found/);
  });

  it("settles once: a second completeWithdraw for the same request rejects", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    const next = (
      await contract.circuits.completeWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      )
    ).context;
    await expect(
      contract.circuits.completeWithdraw(
        next,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Withdrawal not found/);
  });

  it("rejects settling a DEPOSIT request (no refund marker) even with a genuine response", async () => {
    const { contract, ctx } = await deployInitialised();
    const next = (await deposit(contract, ctx, VALID_DEPOSIT)).context;
    const index = toSignBidirectionalEventIndex(
      ledger(next.callContext.currentQueryContext.state).depositEventMap,
    );
    const depositIdHex = first(index.keys(), "signBidirectional request id");
    const depositId = requestIdBytes(depositIdHex);

    await expect(
      contract.circuits.completeWithdraw(
        next,
        depositId,
        respond(MPC_RESPONSE_SECRET, depositId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Withdrawal not found/);
  });
});

// ---- Refund-withdraw tests ----

describe("refundWithdraw settle", () => {
  it("failure output: the WITHDRAWER re-mints the surrendered value and consumes the withdrawal", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();

    // Same shielded-mint reasoning as completeWithdraw's refund branch: the
    // call resolving proves the mint executed, the observable effect is the
    // consumption of the request and its pending-withdrawal marker.
    const next = (
      await contract.circuits.refundWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      )
    ).context;

    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.signBidirectionalEventMap.isEmpty()).toBe(true);
    expect(state.withdrawSettleViews.isEmpty()).toBe(true);
  });

  it("a caller other than the withdrawer cannot take the refund", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    await expect(
      contract.circuits.refundWithdraw(
        await strangerContext("refundWithdraw", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the withdrawer/);
  });

  it("rejects a genuinely attested 5-byte output that is not the failure output", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    // Digest and signature check out, but the bytes are not the sentinel:
    // no refund. Guards against width collisions as respond schemas grow.
    const notTheSentinel = bytes(5, 0x01);
    await expect(
      contract.circuits.refundWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, notTheSentinel),
        notTheSentinel,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the MPC failure output/);
  });

  it("rejects a failure output signed by a key other than the stored MPC response key", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    await expect(
      contract.circuits.refundWithdraw(
        ctx,
        requestId,
        respond(IMPOSTER_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("rejects presented output bytes that differ from what was signed", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    // Signed over some other 5-byte output, presented as the sentinel: the
    // recomputed digest no longer matches what the signature covers, so the
    // signature check rejects it before the sentinel gate.
    await expect(
      contract.circuits.refundWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, bytes(5, 0x01)),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("rejects refunding a DEPOSIT request (no refund marker) even with a genuine failure output", async () => {
    const { contract, ctx } = await deployInitialised();
    const next = (await deposit(contract, ctx, VALID_DEPOSIT)).context;
    const index = toSignBidirectionalEventIndex(
      ledger(next.callContext.currentQueryContext.state).depositEventMap,
    );
    const depositIdHex = first(index.keys(), "signBidirectional request id");
    const depositId = requestIdBytes(depositIdHex);

    await expect(
      contract.circuits.refundWithdraw(
        next,
        depositId,
        respond(MPC_RESPONSE_SECRET, depositId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
      // Deposits never insert the pending-withdrawal marker, so a deposit id
      // cannot be refunded as a withdrawal.
    ).rejects.toThrow(/Withdrawal not found/);
  });

  it("refunds once: a second refund for the same request rejects", async () => {
    const { contract, ctx, requestId } = await withdrawRequested();
    const next = (
      await contract.circuits.refundWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      )
    ).context;
    await expect(
      contract.circuits.refundWithdraw(
        next,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
      // The first refund consumed the pending-withdrawal marker.
    ).rejects.toThrow(/Withdrawal not found/);
  });
});

// ---- Claim-deposit fixtures ----

// The circuit's `Maybe<Either<ZswapCoinPublicKey, ContractAddress>>` recipient
// argument. Compact's Maybe/Either are plain structs: even a `none` (and the
// unused Either side of a `some`) carries a fully default-valued payload so
// the argument stays well-aligned.
const CALLER_RECIPIENT = {
  is_some: false,
  value: {
    is_left: true,
    left: { bytes: new Uint8Array(32) },
    right: { bytes: new Uint8Array(32) },
  },
};
const OTHER_WALLET_RECIPIENT = {
  is_some: true,
  value: {
    is_left: true,
    left: { bytes: bytes(32, 0x21) },
    right: { bytes: new Uint8Array(32) },
  },
};
const CONTRACT_RECIPIENT = {
  is_some: true,
  value: {
    is_left: false,
    left: { bytes: new Uint8Array(32) },
    right: { bytes: hexToBytes(sampleContractAddress()) },
  },
};

/**
 * Deploy + initialise + deposit(VALID_DEPOSIT): the arrange step of
 * every claim test. Returns the pending deposit's request id (the single
 * ledger map key) alongside the threaded context.
 */
const depositRequested = async () => {
  const { contract, ctx } = await deployInitialised();
  const next = (await deposit(contract, ctx, VALID_DEPOSIT)).context;
  const index = toSignBidirectionalEventIndex(
    ledger(next.callContext.currentQueryContext.state).depositEventMap,
  );
  const idHex = first(index.keys(), "signBidirectional request id");
  return { contract, ctx: next, requestId: requestIdBytes(idHex) };
};

// ---- Claim-deposit tests ----

describe("completeDeposit settle", () => {
  // The mint itself is shielded: the call resolving proves it executed, and
  // the publicly-observable effect asserted here is the request's consumption.
  it.each([
    { name: "no recipient: mints to the caller", recipient: CALLER_RECIPIENT },
    {
      name: "an explicit wallet recipient: mints to the given coin public key",
      recipient: OTHER_WALLET_RECIPIENT,
    },
    {
      name: "an explicit contract recipient: mints to the given contract address",
      recipient: CONTRACT_RECIPIENT,
    },
  ])("$name and consumes the request", async ({ recipient }) => {
    const { contract, ctx, requestId } = await depositRequested();

    const next = (
      await contract.circuits.completeDeposit(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        recipient,
      )
    ).context;

    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.depositEventMap.isEmpty()).toBe(true);
    expect(state.depositSettleViews.isEmpty()).toBe(true);
  });

  it("rejects a response signed by a key other than the stored MPC response key", async () => {
    const { contract, ctx, requestId } = await depositRequested();
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        requestId,
        respond(IMPOSTER_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        CALLER_RECIPIENT,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("rejects a genuinely signed sweep that returned false", async () => {
    const { contract, ctx, requestId } = await depositRequested();
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_FALSE),
        OUTPUT_FALSE,
        MINT_NONCE,
        CALLER_RECIPIENT,
      ),
    ).rejects.toThrow(/ERC20 transfer returned false/);
  });

  it("rejects presented output bytes that differ from what was signed", async () => {
    const { contract, ctx, requestId } = await depositRequested();
    // Signed over the FALSE result, presented as a success byte: the digest
    // recomputed in-circuit is not the one the signature covers. This is the
    // attack the signature-only event must stop: claiming a failed sweep as a
    // success. (The reverse presentation would trip the return-value assert
    // first.)
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_FALSE),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        CALLER_RECIPIENT,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("rejects a genuinely signed id that has no pending deposit", async () => {
    const { contract, ctx } = await depositRequested();
    const unknownId = bytes(32, 0xab);
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        unknownId,
        respond(MPC_RESPONSE_SECRET, unknownId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        CALLER_RECIPIENT,
      ),
    ).rejects.toThrow(/Deposit not found/);
  });

  it("claims once: a second claim for the same request rejects", async () => {
    const { contract, ctx, requestId } = await depositRequested();
    const next = (
      await contract.circuits.completeDeposit(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        CALLER_RECIPIENT,
      )
    ).context;
    await expect(
      contract.circuits.completeDeposit(
        next,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        CALLER_RECIPIENT,
      ),
      // The first claim consumed the deposit entry and its settle view.
    ).rejects.toThrow(/Deposit not found/);
  });

  it("rejects a caller other than the original depositor, even one naming themselves recipient", async () => {
    // The settle view pins the DEPOSITOR's identity commitment, and the
    // stranger's witness recomputes a different one.
    const { contract, ctx, requestId } = await depositRequested();
    await expect(
      contract.circuits.completeDeposit(
        await strangerContext("completeDeposit", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        OTHER_WALLET_RECIPIENT,
      ),
    ).rejects.toThrow(/Not the depositor/);
  });
});

// ============================ Swap (Uniswap V3) =============================

const EXACT_OUTPUT_SINGLE_SELECTOR = new Uint8Array([0x50, 0x23, 0xb4, 0xdf]);
const APPROVE_SELECTOR = new Uint8Array([0x09, 0x5e, 0xa7, 0xb3]);
const MAX_APPROVE = pureCircuits.unlimitedAllowance();
// exactOutputSingle returns amountIn: the MPC decodes it as uint256, re-packs it as uint64.
const SWAP_OUTPUT_SCHEMA = asciiPadded('[{"name":"amountIn","type":"uint256"}]', 38);
const SWAP_RESPOND_SCHEMA = asciiPadded('[{"name":"amountIn","type":"uint64"}]', 37);

// A second ERC20 (tokenOut) with its own vault-token color.
const ERC20_OUT = bytes(20, 0xbb);
const VAULT_TOKEN_COLOR_OUT = hexToBytes(
  rawTokenType(pureCircuits.vaultTokenDomainSeparator(ERC20_OUT), VAULT_ADDRESS),
);
const FEE = 500n;
const SWAP_AMOUNT_OUT = 995_000n; // exact tokenOut received
const SWAP_AMOUNT_IN_MAX = AMOUNT; // spend cap = the surrendered coin
const SWAP_AMOUNT_IN_SPENT = 990_000n; // attested input actually spent (<= the cap)

interface SwapCallArgs {
  evmNonce: bigint;
  keyVersion: bigint;
  swap: {
    tokenIn: Uint8Array;
    tokenOut: Uint8Array;
    fee: bigint;
    amountOut: bigint;
    amountInMaximum: bigint;
  };
  coin: ReturnType<typeof vaultCoin>;
}

const VALID_SWAP: SwapCallArgs = {
  evmNonce: 0n,
  keyVersion: 1n,
  swap: {
    tokenIn: ERC20,
    tokenOut: ERC20_OUT,
    fee: FEE,
    amountOut: SWAP_AMOUNT_OUT,
    amountInMaximum: SWAP_AMOUNT_IN_MAX,
  },
  coin: vaultCoin(SWAP_AMOUNT_IN_MAX),
};

const swap = (
  contract: Contract<VaultPrivateState>,
  ctx: Parameters<Contract<VaultPrivateState>["circuits"]["startSwap"]>[0],
  args: SwapCallArgs,
) => contract.circuits.startSwap(ctx, args.evmNonce, args.keyVersion, args.swap, args.coin);

// A successful swap's attested output: the amountIn spent as the MPC serializes it — a
// Midnight-native little-endian uint64 (8 bytes), the twin of serializeRespondOutput.
// completeSwap native-deserializes it.
const swapOutput = (amountIn: bigint): Uint8Array => {
  const b = new Uint8Array(8);
  let v = amountIn;
  for (let i = 0; i < 8 && v > 0n; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
};
const OUTPUT_SWAP = swapOutput(SWAP_AMOUNT_IN_SPENT);

describe("approveRouter", () => {
  it("records an approve(router, ~unlimited) on signBidirectionalEventMap from the vault path, no coin", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = await contract.circuits.approveRouter(ctx, ERC20, 0n, 1n);

    const index = toSignBidirectionalEventIndex(
      ledger(next.callContext.currentQueryContext.state).signBidirectionalEventMap,
    );
    expect(index.size).toBe(1);
    const [, record] = first(index.entries(), "indexed approveRouter request");

    // Vault path, approve ON the erc20, spender = pinned router, amount = MAX.
    expect(record.path).toEqual(asciiPadded("vault", 32));
    expect(record.txParams.to).toEqual(ERC20);
    const { calldata } = record.txParams;
    expect(calldata.is_some).toBe(true);
    expect(calldata.value.selector).toEqual(APPROVE_SELECTOR);
    expect(calldata.value.noWords).toBe(2n);
    expect(calldata.value.words[0]).toEqual(evmAddressAbiWord(ROUTER));
    expect(calldata.value.words[1]).toEqual(numericAbiWord(MAX_APPROVE));
  });

  it("is permissionless (a stranger may ready a token) and needs initialise", async () => {
    const { contract, ctx } = await deployContract();
    await expect(contract.circuits.approveRouter(ctx, ERC20, 0n, 1n)).rejects.toThrow(
      /Not initialised/,
    );
    const ready = await deployInitialised();
    await expect(
      ready.contract.circuits.approveRouter(
        await strangerContext("approveRouter", ready.ctx),
        ERC20,
        0n,
        1n,
      ),
    ).resolves.toBeDefined();
  });
});

describe("swap round-trip", () => {
  it("burns tokenIn and stores a vault-path exactOutputSingle event on the swap map", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = await swap(contract, ctx, VALID_SWAP);
    const state = ledger(next.callContext.currentQueryContext.state);

    const index = toSignBidirectionalEventIndex(state.swapEventMap);
    expect(index.size).toBe(1);
    // Field 0 stays empty: the swap went to the swap map, not the transfer map.
    expect(state.signBidirectionalEventMap.isEmpty()).toBe(true);
    const [idHex, record] = first(index.entries(), "indexed swap request");

    expect(record.sender).toEqual({ bytes: VAULT_ADDRESS_BYTES });
    expect(record.path).toEqual(asciiPadded("vault", 32));

    // Contract-fixed envelope: to = pinned router, vault-paid gas.
    const { calldata, ...envelope } = record.txParams;
    expect(envelope).toEqual({
      to: ROUTER,
      chainId: CHAIN_ID,
      nonce: VALID_SWAP.evmNonce,
      gasLimit: 700_000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
    });
    expect(record.outputDeserializationSchema).toEqual(SWAP_OUTPUT_SCHEMA);
    expect(record.respondSerializationSchema).toEqual(SWAP_RESPOND_SCHEMA);

    // exactOutputSingle((tokenIn, tokenOut, fee, recipient=vault, amountOut, amountInMaximum, 0)).
    expect(calldata.is_some).toBe(true);
    expect(calldata.value.selector).toEqual(EXACT_OUTPUT_SINGLE_SELECTOR);
    expect(calldata.value.noWords).toBe(7n);
    expect(calldata.value.words[0]).toEqual(evmAddressAbiWord(ERC20));
    expect(calldata.value.words[1]).toEqual(evmAddressAbiWord(ERC20_OUT));
    expect(calldata.value.words[2]).toEqual(numericAbiWord(FEE));
    expect(calldata.value.words[3]).toEqual(evmAddressAbiWord(VAULT_EVM));
    expect(calldata.value.words[4]).toEqual(numericAbiWord(SWAP_AMOUNT_OUT));
    expect(calldata.value.words[5]).toEqual(numericAbiWord(SWAP_AMOUNT_IN_MAX));
    expect(calldata.value.words[6]).toEqual(numericAbiWord(0n));

    // Pending-swap marker pinned.
    expect(state.swapSettleViews.member(requestIdBytes(idHex))).toBe(true);

    // Same burn as withdraw (which asserts the receive/spend pairing in
    // detail): amountInMaximum of the tokenIn vault coin is received, spent,
    // and paid whole to the shielded burn address.
    const zswap = zswapState(next);

    // check inputs, expect 1 input:
    // - coin for the amount being withdrawn
    expect(zswap.inputs).toHaveLength(1);
    const consumed = first(zswap.inputs, "consumed coin");
    expect(consumed.color).toEqual(VAULT_TOKEN_COLOR);
    expect(consumed.value).toBe(SWAP_AMOUNT_IN_MAX);

    // check outputs, expect 2 ouputs:
    // - received coin to the contract address
    // - burned coin to the burn address
    expect(zswap.outputs).toHaveLength(2);

    // received coin to the contract address
    const received = first(
      zswap.outputs.filter((output) => !output.recipient.is_left),
      "contract-owned receive output",
    );
    expect(received.recipient.right.bytes).toEqual(VAULT_ADDRESS_BYTES);
    expect(received.coinInfo).toEqual({
      nonce: consumed.nonce,
      color: consumed.color,
      value: consumed.value,
    });

    // burned coin to the burn address
    const burnOutput = first(
      zswap.outputs.filter((output) => output.recipient.is_left),
      "burn output",
    );
    expect(burnOutput.coinInfo.color).toEqual(VAULT_TOKEN_COLOR);
    expect(burnOutput.coinInfo.value).toBe(SWAP_AMOUNT_IN_MAX);
    expect(burnOutput.recipient.left.bytes).toEqual(BURN_ADDRESS_BYTES);
  });

  it("rejects a coin that is not the tokenIn vault color or not amountInMaximum", async () => {
    const { contract, ctx } = await deployInitialised();
    await expect(
      swap(contract, ctx, { ...VALID_SWAP, coin: vaultCoin(AMOUNT, VAULT_TOKEN_COLOR_OUT) }),
    ).rejects.toThrow(/Coin is not the vault token for tokenIn/);
    await expect(
      swap(contract, ctx, { ...VALID_SWAP, coin: vaultCoin(SWAP_AMOUNT_IN_MAX + 1n) }),
    ).rejects.toThrow(/Coin value must equal amountInMaximum/);
  });
});

// ---- Swap settle fixtures ----

const swapRequested = async () => {
  const { contract, ctx } = await deployInitialised();
  const next = (await swap(contract, ctx, VALID_SWAP)).context;
  const index = toSignBidirectionalEventIndex(
    ledger(next.callContext.currentQueryContext.state).swapEventMap,
  );
  const idHex = first(index.keys(), "indexed swap request");
  return { contract, ctx: next, requestId: requestIdBytes(idHex) };
};

describe("completeSwap settle", () => {
  it("verifies the amountIn attestation, mints tokenOut + change, and cleans up (swapper-gated)", async () => {
    const { contract, ctx, requestId } = await swapRequested();
    const next = (
      await contract.circuits.completeSwap(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SWAP),
        OUTPUT_SWAP,
        MINT_NONCE,
        CHANGE_NONCE,
      )
    ).context;
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.swapEventMap.isEmpty()).toBe(true);
    expect(state.swapSettleViews.isEmpty()).toBe(true);
  });

  it("a caller other than the swapper cannot take the minted tokenOut", async () => {
    const { contract, ctx, requestId } = await swapRequested();
    await expect(
      contract.circuits.completeSwap(
        await strangerContext("completeSwap", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SWAP),
        OUTPUT_SWAP,
        MINT_NONCE,
        CHANGE_NONCE,
      ),
    ).rejects.toThrow(/Not the swapper/);
  });

  it("rejects a changeNonce equal to mintNonce (the two coins must not share a nonce)", async () => {
    const { contract, ctx, requestId } = await swapRequested();
    await expect(
      contract.circuits.completeSwap(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SWAP),
        OUTPUT_SWAP,
        MINT_NONCE,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/changeNonce must differ from mintNonce/);
  });

  it("rejects an attestation signed by the wrong key, and presented bytes that differ", async () => {
    const { contract, ctx, requestId } = await swapRequested();
    await expect(
      contract.circuits.completeSwap(
        ctx,
        requestId,
        respond(IMPOSTER_SECRET, requestId, OUTPUT_SWAP),
        OUTPUT_SWAP,
        MINT_NONCE,
        CHANGE_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
    await expect(
      contract.circuits.completeSwap(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SWAP),
        swapOutput(1n),
        MINT_NONCE,
        CHANGE_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });
  it("rejects a failure attestation presented as a zero-padded success output", async () => {
    const { contract, ctx, requestId } = await swapRequested();
    const padded = new Uint8Array(8);
    padded.set(OUTPUT_REVERTED);
    await expect(
      contract.circuits.completeSwap(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        padded,
        MINT_NONCE,
        CHANGE_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });
});

describe("refundSwap settle", () => {
  it("on the MPC failure output, re-mints tokenIn to the swapper and cleans up", async () => {
    const { contract, ctx, requestId } = await swapRequested();
    const next = (
      await contract.circuits.refundSwap(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      )
    ).context;
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.swapEventMap.isEmpty()).toBe(true);
    expect(state.swapSettleViews.isEmpty()).toBe(true);
  });

  it("is swapper-gated", async () => {
    const { contract, ctx, requestId } = await swapRequested();
    await expect(
      contract.circuits.refundSwap(
        await strangerContext("refundSwap", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the swapper/);
  });
});

// ---- Aave: supply/redeem fixtures ----

const DEPOSIT_SELECTOR = new Uint8Array([0x6e, 0x55, 0x3f, 0x65]);
const REDEEM_SELECTOR = new Uint8Array([0xba, 0x08, 0x76, 0x52]);
const SUPPLY_OUTPUT_SCHEMA = asciiPadded('[{"name":"shares","type":"uint256"}]', 36);
const SUPPLY_RESPOND_SCHEMA = asciiPadded('[{"name":"shares","type":"uint64"}]', 35);
const REDEEM_OUTPUT_SCHEMA = asciiPadded('[{"name":"assets","type":"uint256"}]', 36);
const REDEEM_RESPOND_SCHEMA = asciiPadded('[{"name":"assets","type":"uint64"}]', 35);

// Vault-token colours of the pinned pair, computed like a wallet (off-chain twin
// of the in-circuit tokenType(domainSep, kernel.self())).
const STATA_UNDERLYING_COLOR = hexToBytes(
  rawTokenType(pureCircuits.vaultTokenDomainSeparator(STATA_UNDERLYING), VAULT_ADDRESS),
);
const STATA_COLOR = hexToBytes(
  rawTokenType(pureCircuits.vaultTokenDomainSeparator(STATA_TOKEN), VAULT_ADDRESS),
);

const SUPPLY_AMOUNT = AMOUNT; // USDC surrendered
const SUPPLY_SHARES = 360_679n; // attested stataUSDC shares minted
const REDEEM_SHARES = AMOUNT; // stataUSDC surrendered
const REDEEM_ASSETS = 2_780_944n; // attested USDC assets minted (principal + interest)

const supply = (
  contract: Contract<VaultPrivateState>,
  ctx: Parameters<Contract<VaultPrivateState>["circuits"]["startSupply"]>[0],
  amount: bigint,
  coin: ReturnType<typeof vaultCoin>,
) => contract.circuits.startSupply(ctx, 0n, 1n, amount, coin);

const redeem = (
  contract: Contract<VaultPrivateState>,
  ctx: Parameters<Contract<VaultPrivateState>["circuits"]["startRedeem"]>[0],
  shares: bigint,
  coin: ReturnType<typeof vaultCoin>,
) => contract.circuits.startRedeem(ctx, 0n, 1n, shares, coin);

describe("approveStata", () => {
  it("records approve(stataToken, MAX) on signBidirectionalEventMap from the vault path, to = the underlying", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = await contract.circuits.approveStata(ctx, 0n, 1n);

    const index = toSignBidirectionalEventIndex(
      ledger(next.callContext.currentQueryContext.state).signBidirectionalEventMap,
    );
    expect(index.size).toBe(1);
    const [, record] = first(index.entries(), "indexed approveStata request");
    expect(record.path).toEqual(asciiPadded("vault", 32));
    // approve is called ON the underlying USDC, spender = the pinned wrapper.
    expect(record.txParams.to).toEqual(STATA_UNDERLYING);
    const { calldata } = record.txParams;
    expect(calldata.value.selector).toEqual(APPROVE_SELECTOR);
    expect(calldata.value.words[0]).toEqual(evmAddressAbiWord(STATA_TOKEN));
    expect(calldata.value.words[1]).toEqual(numericAbiWord(MAX_APPROVE));
  });
});

describe("supply round-trip", () => {
  it("burns the underlying and stores a vault-path deposit event on the supply map", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = await supply(
      contract,
      ctx,
      SUPPLY_AMOUNT,
      vaultCoin(SUPPLY_AMOUNT, STATA_UNDERLYING_COLOR),
    );
    const state = ledger(next.callContext.currentQueryContext.state);

    const index = toSignBidirectionalEventIndex(state.supplyEventMap);
    expect(index.size).toBe(1);
    const [idHex, record] = first(index.entries(), "indexed supply request");
    expect(record.sender).toEqual({ bytes: VAULT_ADDRESS_BYTES });
    expect(record.path).toEqual(asciiPadded("vault", 32));
    expect(record.txParams.to).toEqual(STATA_TOKEN);
    expect(record.outputDeserializationSchema).toEqual(SUPPLY_OUTPUT_SCHEMA);
    expect(record.respondSerializationSchema).toEqual(SUPPLY_RESPOND_SCHEMA);

    // deposit(amount, receiver=vault).
    const { calldata } = record.txParams;
    expect(calldata.value.selector).toEqual(DEPOSIT_SELECTOR);
    expect(calldata.value.noWords).toBe(2n);
    expect(calldata.value.words[0]).toEqual(numericAbiWord(SUPPLY_AMOUNT));
    expect(calldata.value.words[1]).toEqual(evmAddressAbiWord(VAULT_EVM));

    expect(state.supplySettleViews.member(requestIdBytes(idHex))).toBe(true);

    // Same burn as withdraw (which asserts the receive/spend pairing in
    // detail): the underlying vault coin is received, spent, and paid whole to
    // the shielded burn address.
    const zswap = zswapState(next);

    expect(zswap.inputs).toHaveLength(1);
    const consumed = first(zswap.inputs, "consumed coin");
    expect(consumed.color).toEqual(STATA_UNDERLYING_COLOR);
    expect(consumed.value).toBe(SUPPLY_AMOUNT);

    expect(zswap.outputs).toHaveLength(2);

    // received coin to the contract address (the receive/spend transient)
    const received = first(
      zswap.outputs.filter((output) => !output.recipient.is_left),
      "contract-owned receive output",
    );
    expect(received.recipient.right.bytes).toEqual(VAULT_ADDRESS_BYTES);
    expect(received.coinInfo).toEqual({
      nonce: consumed.nonce,
      color: consumed.color,
      value: consumed.value,
    });

    // burned coin to the burn address
    const burnOutput = first(
      zswap.outputs.filter((output) => output.recipient.is_left),
      "burn output",
    );
    expect(burnOutput.coinInfo.color).toEqual(STATA_UNDERLYING_COLOR);
    expect(burnOutput.coinInfo.value).toBe(SUPPLY_AMOUNT);
    expect(burnOutput.recipient.left.bytes).toEqual(BURN_ADDRESS_BYTES);
  });

  it("rejects a coin that is not the underlying color or not the amount", async () => {
    const { contract, ctx } = await deployInitialised();
    await expect(
      supply(contract, ctx, SUPPLY_AMOUNT, vaultCoin(SUPPLY_AMOUNT, STATA_COLOR)),
    ).rejects.toThrow(/Coin is not the vault token for the underlying/);
    await expect(
      supply(contract, ctx, SUPPLY_AMOUNT, vaultCoin(SUPPLY_AMOUNT + 1n, STATA_UNDERLYING_COLOR)),
    ).rejects.toThrow(/Coin value must equal amount/);
  });

  it("rejects a zero amount and an amount past the Uint<64> refund cap", async () => {
    const { contract, ctx } = await deployInitialised();
    await expect(supply(contract, ctx, 0n, vaultCoin(0n, STATA_UNDERLYING_COLOR))).rejects.toThrow(
      /amount must be positive/,
    );
    const overCap = 1n << 64n;
    await expect(
      supply(contract, ctx, overCap, vaultCoin(overCap, STATA_UNDERLYING_COLOR)),
    ).rejects.toThrow(/amount exceeds Uint<64> max/);
  });
});

const supplyRequested = async () => {
  const { contract, ctx } = await deployInitialised();
  const next = (
    await supply(contract, ctx, SUPPLY_AMOUNT, vaultCoin(SUPPLY_AMOUNT, STATA_UNDERLYING_COLOR))
  ).context;
  const index = toSignBidirectionalEventIndex(
    ledger(next.callContext.currentQueryContext.state).supplyEventMap,
  );
  const idHex = first(index.keys(), "indexed supply request");
  return { contract, ctx: next, requestId: requestIdBytes(idHex) };
};

describe("completeSupply settle", () => {
  it("verifies the shares attestation, mints stataToken, and cleans up (supplier-gated)", async () => {
    const { contract, ctx, requestId } = await supplyRequested();
    const out = swapOutput(SUPPLY_SHARES);
    const next = (
      await contract.circuits.completeSupply(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, out),
        out,
        MINT_NONCE,
      )
    ).context;
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.supplyEventMap.isEmpty()).toBe(true);
    expect(state.supplySettleViews.isEmpty()).toBe(true);
  });

  it("a caller other than the supplier cannot take the minted shares", async () => {
    const { contract, ctx, requestId } = await supplyRequested();
    const out = swapOutput(SUPPLY_SHARES);
    await expect(
      contract.circuits.completeSupply(
        await strangerContext("completeSupply", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, out),
        out,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the supplier/);
  });
});

describe("redeem round-trip", () => {
  it("burns the stataToken and stores a vault-path redeem event on the redeem map", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = await redeem(
      contract,
      ctx,
      REDEEM_SHARES,
      vaultCoin(REDEEM_SHARES, STATA_COLOR),
    );
    const state = ledger(next.callContext.currentQueryContext.state);

    const index = toSignBidirectionalEventIndex(state.redeemEventMap);
    expect(index.size).toBe(1);
    const [idHex, record] = first(index.entries(), "indexed redeem request");
    expect(record.txParams.to).toEqual(STATA_TOKEN);
    expect(record.outputDeserializationSchema).toEqual(REDEEM_OUTPUT_SCHEMA);
    expect(record.respondSerializationSchema).toEqual(REDEEM_RESPOND_SCHEMA);

    // redeem(shares, receiver=vault, owner=vault).
    const { calldata } = record.txParams;
    expect(calldata.value.selector).toEqual(REDEEM_SELECTOR);
    expect(calldata.value.noWords).toBe(3n);
    expect(calldata.value.words[0]).toEqual(numericAbiWord(REDEEM_SHARES));
    expect(calldata.value.words[1]).toEqual(evmAddressAbiWord(VAULT_EVM));
    expect(calldata.value.words[2]).toEqual(evmAddressAbiWord(VAULT_EVM));

    expect(state.redeemSettleViews.member(requestIdBytes(idHex))).toBe(true);

    // Same burn as supply: the wrapper vault coin is received, spent, and paid
    // whole to the shielded burn address.
    const zswap = zswapState(next);

    expect(zswap.inputs).toHaveLength(1);
    const consumed = first(zswap.inputs, "consumed coin");
    expect(consumed.color).toEqual(STATA_COLOR);
    expect(consumed.value).toBe(REDEEM_SHARES);

    expect(zswap.outputs).toHaveLength(2);

    // received coin to the contract address (the receive/spend transient)
    const received = first(
      zswap.outputs.filter((output) => !output.recipient.is_left),
      "contract-owned receive output",
    );
    expect(received.recipient.right.bytes).toEqual(VAULT_ADDRESS_BYTES);
    expect(received.coinInfo).toEqual({
      nonce: consumed.nonce,
      color: consumed.color,
      value: consumed.value,
    });

    // burned coin to the burn address
    const burnOutput = first(
      zswap.outputs.filter((output) => output.recipient.is_left),
      "burn output",
    );
    expect(burnOutput.coinInfo.color).toEqual(STATA_COLOR);
    expect(burnOutput.coinInfo.value).toBe(REDEEM_SHARES);
    expect(burnOutput.recipient.left.bytes).toEqual(BURN_ADDRESS_BYTES);
  });

  it("rejects a coin that is not the wrapper color or not the shares", async () => {
    const { contract, ctx } = await deployInitialised();
    await expect(
      redeem(contract, ctx, REDEEM_SHARES, vaultCoin(REDEEM_SHARES, STATA_UNDERLYING_COLOR)),
    ).rejects.toThrow(/Coin is not the vault token for the wrapper/);
    await expect(
      redeem(contract, ctx, REDEEM_SHARES, vaultCoin(REDEEM_SHARES + 1n, STATA_COLOR)),
    ).rejects.toThrow(/Coin value must equal shares/);
  });

  it("rejects zero shares and shares past the Uint<64> refund cap", async () => {
    const { contract, ctx } = await deployInitialised();
    await expect(redeem(contract, ctx, 0n, vaultCoin(0n, STATA_COLOR))).rejects.toThrow(
      /shares must be positive/,
    );
    const overCap = 1n << 64n;
    await expect(redeem(contract, ctx, overCap, vaultCoin(overCap, STATA_COLOR))).rejects.toThrow(
      /shares exceeds Uint<64> max/,
    );
  });
});

const redeemRequested = async () => {
  const { contract, ctx } = await deployInitialised();
  const next = (await redeem(contract, ctx, REDEEM_SHARES, vaultCoin(REDEEM_SHARES, STATA_COLOR)))
    .context;
  const index = toSignBidirectionalEventIndex(
    ledger(next.callContext.currentQueryContext.state).redeemEventMap,
  );
  const idHex = first(index.keys(), "indexed redeem request");
  return { contract, ctx: next, requestId: requestIdBytes(idHex) };
};

describe("completeRedeem settle", () => {
  it("a caller other than the redeemer cannot take the minted underlying", async () => {
    const { contract, ctx, requestId } = await redeemRequested();
    const out = swapOutput(REDEEM_ASSETS);
    await expect(
      contract.circuits.completeRedeem(
        await strangerContext("completeRedeem", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, out),
        out,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the redeemer/);
  });

  it("verifies the assets attestation, mints the underlying, and cleans up", async () => {
    const { contract, ctx, requestId } = await redeemRequested();
    const out = swapOutput(REDEEM_ASSETS);
    const next = (
      await contract.circuits.completeRedeem(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, out),
        out,
        MINT_NONCE,
      )
    ).context;
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.redeemEventMap.isEmpty()).toBe(true);
    expect(state.redeemSettleViews.isEmpty()).toBe(true);
  });
});

describe("refundSupply / refundRedeem settle", () => {
  it("supply: on the MPC failure output, re-mints the underlying to the supplier and cleans up", async () => {
    const { contract, ctx, requestId } = await supplyRequested();
    const next = (
      await contract.circuits.refundSupply(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      )
    ).context;
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.supplyEventMap.isEmpty()).toBe(true);
    expect(state.supplySettleViews.isEmpty()).toBe(true);
  });

  it("redeem: on the MPC failure output, re-mints the stataToken to the redeemer and cleans up", async () => {
    const { contract, ctx, requestId } = await redeemRequested();
    const next = (
      await contract.circuits.refundRedeem(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      )
    ).context;
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.redeemEventMap.isEmpty()).toBe(true);
    expect(state.redeemSettleViews.isEmpty()).toBe(true);
  });

  it("is supplier/redeemer-gated (a stranger cannot trigger the re-mint)", async () => {
    const { contract, ctx, requestId } = await supplyRequested();
    await expect(
      contract.circuits.refundSupply(
        await strangerContext("refundSupply", ctx),
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the supplier/);
  });
});

// ---- Cross-kind settle isolation ----

// Every settle circuit takes the same shaped arguments under one signature
// scheme, so a genuine attestation for ANY request id verifies in all of them.
// The per-kind map membership assert is the whole barrier, and this matrix
// exercises it: each kind's id against every OTHER kind's settle and refund
// circuit.

/** A request kind that pins a settle view under its own event map. */
enum SettleKind {
  Deposit = "deposit",
  Withdraw = "withdraw",
  Swap = "swap",
  Supply = "supply",
  Redeem = "redeem",
}

/** A started request: the threaded context plus the id its ledger map keyed it by. */
interface PendingRequest {
  contract: Contract<VaultPrivateState>;
  ctx: CircuitContext<VaultPrivateState>;
  requestId: RequestId;
}

/**
 * Deploy + initialise + approveRouter(ERC20). The recorded request lands on
 * signBidirectionalEventMap under the vault path, and no settle circuit
 * consumes it.
 */
const approveRouterRequested = async (): Promise<PendingRequest> => {
  const { contract, ctx } = await deployInitialised();
  const next = (await contract.circuits.approveRouter(ctx, ERC20, 0n, 1n)).context;
  const index = toSignBidirectionalEventIndex(
    ledger(next.callContext.currentQueryContext.state).signBidirectionalEventMap,
  );
  const idHex = first(index.keys(), "indexed approveRouter request");
  return { contract, ctx: next, requestId: requestIdBytes(idHex) };
};

const OUTPUT_SUPPLY = swapOutput(SUPPLY_SHARES);
const OUTPUT_REDEEM = swapOutput(REDEEM_ASSETS);

/** One column of the matrix: a settle circuit, and the guard a foreign id must trip. */
interface CrossKindTarget {
  /** The kind whose requests this circuit settles. */
  kind: SettleKind;
  /** Circuit name, completing the title "... presented to <circuit>". */
  circuit: string;
  /** Calls the circuit with an attestation genuinely signed for the presented id. */
  settle: (pending: PendingRequest) => Promise<CircuitResults<VaultPrivateState, []>>;
  /** Error the circuit must throw on an id of another kind. */
  throws: RegExp;
}

const CROSS_KIND_TARGETS: CrossKindTarget[] = [
  {
    kind: SettleKind.Deposit,
    circuit: "completeDeposit",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.completeDeposit(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
        CALLER_RECIPIENT,
      ),
    throws: /Deposit not found/,
  },
  {
    kind: SettleKind.Withdraw,
    circuit: "completeWithdraw",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.completeWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    throws: /Withdrawal not found/,
  },
  {
    kind: SettleKind.Withdraw,
    circuit: "refundWithdraw",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.refundWithdraw(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    throws: /Withdrawal not found/,
  },
  {
    kind: SettleKind.Swap,
    circuit: "completeSwap",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.completeSwap(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SWAP),
        OUTPUT_SWAP,
        MINT_NONCE,
        CHANGE_NONCE,
      ),
    throws: /Swap not found/,
  },
  {
    kind: SettleKind.Swap,
    circuit: "refundSwap",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.refundSwap(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    throws: /Swap not found/,
  },
  {
    kind: SettleKind.Supply,
    circuit: "completeSupply",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.completeSupply(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_SUPPLY),
        OUTPUT_SUPPLY,
        MINT_NONCE,
      ),
    throws: /Supply not found/,
  },
  {
    kind: SettleKind.Supply,
    circuit: "refundSupply",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.refundSupply(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    throws: /Supply not found/,
  },
  {
    kind: SettleKind.Redeem,
    circuit: "completeRedeem",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.completeRedeem(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REDEEM),
        OUTPUT_REDEEM,
        MINT_NONCE,
      ),
    throws: /Redeem not found/,
  },
  {
    kind: SettleKind.Redeem,
    circuit: "refundRedeem",
    settle: ({ contract, ctx, requestId }) =>
      contract.circuits.refundRedeem(
        ctx,
        requestId,
        respond(MPC_RESPONSE_SECRET, requestId, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    throws: /Redeem not found/,
  },
];

/** One row of the matrix: the kind of request whose id gets presented. */
interface CrossKindPresented {
  /** The started request's kind, naming the columns it is legitimately settled by. */
  kind: SettleKind;
  /** Arrange: deploy, initialise and start one request of this kind. */
  start: () => Promise<PendingRequest>;
}

const CROSS_KIND_PRESENTED: CrossKindPresented[] = [
  { kind: SettleKind.Deposit, start: depositRequested },
  { kind: SettleKind.Withdraw, start: withdrawRequested },
  { kind: SettleKind.Swap, start: swapRequested },
  { kind: SettleKind.Supply, start: supplyRequested },
  { kind: SettleKind.Redeem, start: redeemRequested },
];

describe("cross-kind settle isolation", () => {
  it.each(
    CROSS_KIND_PRESENTED.flatMap(({ kind, start }) =>
      CROSS_KIND_TARGETS.filter((target) => target.kind !== kind).map((target) => ({
        presented: kind,
        start,
        ...target,
      })),
    ),
  )("rejects a $presented request id presented to $circuit", async ({ start, settle, throws }) => {
    await expect(settle(await start())).rejects.toThrow(throws);
  });

  // The approves record on signBidirectionalEventMap and pin no settle view, so
  // no settle circuit accepts one either.
  it.each(CROSS_KIND_TARGETS)(
    "rejects an approveRouter request id presented to $circuit",
    async ({ settle, throws }) => {
      await expect(settle(await approveRouterRequested())).rejects.toThrow(throws);
    },
  );
});
