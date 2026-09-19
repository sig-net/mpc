// JSON-lines bridge to the Rust real-MPC stack. All chain operations use the
// fixture deploy and flow functions; this process owns no stack.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  deriveEvmAddress,
  parseSecp256k1PublicKey,
  requestIdBytes,
  type RequestIdHex,
} from "@sig-net/midnight";
import { deploySignetContract, type MidnightNodeConfig } from "@sig-net/midnight-contract-deploy";
import {
  AAVE_USDC,
  readVaultLedger,
  STATA_USDC,
  VAULT_DEPOSIT_REQUESTS_PATH,
  VAULT_REDEEM_REQUESTS_PATH,
  VAULT_REQUESTS_PATH,
  VAULT_SUPPLY_REQUESTS_PATH,
  VAULT_SWAP_REQUESTS_PATH,
} from "./contract/src/index.ts";
import { deployVault } from "./deploy/deploy-vault.ts";
import { initialiseVault, resolveInitialiseConfig } from "./deploy/initialise-vault.ts";
import { getErc20Balance, getTransactionNonce } from "./test-harness/evm.ts";
import { JsonRpcProvider } from "ethers";

import { isAnvil } from "./flows/evm-anvil.ts";
import { quoteExactOutputSingle } from "./flows/evm-swap.ts";
import { approveRouter } from "./flows/approve-router.ts";
import { approveStata } from "./flows/approve-stata.ts";
import { broadcastEvm } from "./flows/broadcast-evm.ts";
import { settleDeposit } from "./flows/complete-deposit.ts";
import { completeRedeem } from "./flows/complete-redeem.ts";
import { completeSupply } from "./flows/complete-supply.ts";
import { completeSwap } from "./flows/complete-swap.ts";
import { settleWithdraw } from "./flows/complete-withdraw.ts";
import { pollRespondBidirectional } from "./flows/poll-respond-bidirectional.ts";
import { pollSignatureResponse } from "./flows/poll-signature-response.ts";
import { startDeposit } from "./flows/start-deposit.ts";
import { startRedeem } from "./flows/start-redeem.ts";
import { startSupply } from "./flows/start-supply.ts";
import { startSwap } from "./flows/start-swap.ts";
import { startWithdraw } from "./flows/start-withdraw.ts";
import { dealForkEvmAccounts, SEPOLIA_USDC } from "./flows/fork-funding.ts";
import type { VaultContext } from "./flows/vault-context.ts";
import { resolveUserIdentity } from "./flows/vault-identity.ts";
import { createVaultSession, type VaultSession } from "./flows/vault-session.ts";
import { vaultTokenType } from "./flows/vault-token.ts";
import { DEPLOYER_SEED, fundRoles, PUBLISHER_SEED, USER_SEED } from "./funding.ts";

enum Command {
  Bootstrap = "bootstrap",
  Initialise = "initialise",
  RunVault = "runVault",
  Shutdown = "shutdown",
}
type Request =
  | { op: Command.Bootstrap; config: MidnightNodeConfig; artifactDir: string; mpcPublicKey: string }
  | { op: Command.Initialise; responsePublicKey: string }
  | { op: Command.RunVault; evmRpcUrl: string }
  | { op: Command.Shutdown };
enum Phase {
  Starting = "starting",
  Requested = "requested",
  Signed = "signed",
  Broadcast = "broadcast",
  Attested = "attested",
  Complete = "complete",
  Failed = "failed",
  Blocked = "blocked",
}
enum Operation {
  Deposit = "deposit",
  Withdraw = "withdraw",
  DepositSwap = "depositSwap",
  ApproveRouter = "approveRouter",
  Swap = "swap",
  DepositSupply = "depositSupply",
  ApproveStata = "approveStata",
  Supply = "supply",
  Redeem = "redeem",
}
interface OperationEvidence {
  operation: Operation;
  phase: Phase;
  requestId?: RequestIdHex;
  succeeded: boolean;
  evmTransactionHash?: string;
  error?: string;
  failedPhase?: Phase;
  blockedBy?: Operation[];
}
interface ActiveSession {
  env: NodeJS.ProcessEnv;
  artifactDir: string;
  vaultAddress: string;
  mpcPublicKey: string;
  responsePublicKey?: string;
  vaultSession?: VaultSession;
  operations: OperationEvidence[];
  current?: OperationEvidence;
  error?: string;
}
let active: ActiveSession | undefined;

// Keep SDK diagnostics away from the protocol's stdout.
const diagnostics = (...values: unknown[]): void => {
  process.stderr.write(`${values.map(String).join(" ")}\n`);
};
console.log = diagnostics;
console.info = diagnostics;
console.warn = diagnostics;

async function persist(session: ActiveSession): Promise<void> {
  await writeFile(
    join(session.artifactDir, "vault-progress.json"),
    JSON.stringify(
      { vaultAddress: session.vaultAddress, operations: session.operations, error: session.error },
      null,
      2,
    ),
  );
}
async function phase(session: ActiveSession, value: Phase): Promise<void> {
  assert(session.current, "operation is not started");
  session.current.phase = value;
  session.current.succeeded = value === Phase.Complete;
  await persist(session);
  if (value === Phase.Complete) session.current = undefined;
}
async function attempt(
  session: ActiveSession,
  operation: Operation,
  dependencies: Operation[],
  run: () => Promise<void>,
): Promise<void> {
  const blockedBy = dependencies.filter(
    (dependency) =>
      !session.operations.some((entry) => entry.operation === dependency && entry.succeeded),
  );
  const entry: OperationEvidence = { operation, phase: Phase.Starting, succeeded: false };
  session.operations.push(entry);
  if (blockedBy.length > 0) {
    entry.phase = Phase.Blocked;
    entry.blockedBy = blockedBy;
    entry.error = `Required operations did not complete: ${blockedBy.join(", ")}`;
    await persist(session);
    return;
  }
  session.current = entry;
  await persist(session);
  try {
    await run();
    assert(entry.succeeded, "operation did not reach completion");
  } catch (error) {
    entry.failedPhase = entry.phase;
    entry.phase = Phase.Failed;
    entry.succeeded = false;
    entry.error = error instanceof Error ? (error.stack ?? error.message) : String(error);
    diagnostics(`${operation} failed during ${entry.failedPhase}: ${entry.error}`);
    await persist(session);
  } finally {
    session.current = undefined;
  }
}
async function begin(
  session: ActiveSession,
  operation: Operation,
  start: () => Promise<RequestIdHex>,
): Promise<RequestIdHex> {
  const entry = session.current;
  assert(entry?.operation === operation, "operation is not active");
  entry.requestId = await start();
  await phase(session, Phase.Requested);
  return entry.requestId;
}
async function broadcast(
  session: ActiveSession,
  context: VaultContext,
  requestId: RequestIdHex,
  requestsPath: readonly number[],
  expectedSigner = context.evmVaultAddress,
): Promise<void> {
  const transaction = await pollSignatureResponse(context, {
    requestId,
    requestsPath,
    expectedSigner,
    intervalMs: 1000,
    timeoutMs: 180_000,
  });
  await phase(session, Phase.Signed);
  const receipt = await broadcastEvm(context, { transaction });
  assert(session.current);
  session.current.evmTransactionHash = receipt.hash;
  await phase(session, Phase.Broadcast);
}
async function balance(
  session: VaultSession,
  token: string,
  vaultAddress: string,
): Promise<bigint> {
  const state = await (await session.wallet()).facade.waitForSyncedState();
  return state.shielded.balances[vaultTokenType(token, vaultAddress)] ?? 0n;
}
async function deposit(
  session: ActiveSession,
  vaultSession: VaultSession,
  operation: Operation,
  amount: bigint,
  token = SEPOLIA_USDC,
): Promise<void> {
  const context = await vaultSession.vaultContext();
  const before = await balance(vaultSession, token, context.vaultContractAddress);
  const evmBefore = await getErc20Balance(context.evmRpcUrl, token, context.evmVaultAddress);
  const evmNonce = await getTransactionNonce(context.evmRpcUrl, context.evmUserAddress);
  const requestId = await begin(session, operation, () =>
    startDeposit(context, { amount, evmNonce, erc20Address: token }),
  );
  await broadcast(session, context, requestId, VAULT_DEPOSIT_REQUESTS_PATH, context.evmUserAddress);
  const outcome = await pollRespondBidirectional(context, {
    requestId,
    requestsPath: VAULT_DEPOSIT_REQUESTS_PATH,
    timeoutMs: 180_000,
    intervalMs: 1000,
  });
  assert(outcome.succeeded, "deposit attestation must report success");
  await phase(session, Phase.Attested);
  await settleDeposit(context, requestId, outcome);
  assert.equal(
    (
      await readVaultLedger(context.providers.publicDataProvider, context.vaultContractAddress)
    ).depositEventMap.member(requestIdBytes(requestId)),
    false,
  );
  assert.equal((await balance(vaultSession, token, context.vaultContractAddress)) - before, amount);
  assert.equal(
    (await getErc20Balance(context.evmRpcUrl, token, context.evmVaultAddress)).balance -
      evmBefore.balance,
    amount,
  );
  await phase(session, Phase.Complete);
}

async function bootstrap(
  request: Extract<Request, { op: Command.Bootstrap }>,
): Promise<{ centralAddress: string; callerAddress: string; publisherSeed: string }> {
  assert.equal(active, undefined, "driver is already bootstrapped");
  parseSecp256k1PublicKey(request.mpcPublicKey);
  assert.equal(
    request.config.networkId,
    "undeployed",
    "driver only funds a local standalone network",
  );
  await mkdir(request.artifactDir, { recursive: true });
  // The provider uses a relative LevelDB path. Keep it with this run.
  process.chdir(request.artifactDir);
  setNetworkId(request.config.networkId);
  const env: NodeJS.ProcessEnv = {
    NETWORK_ID: request.config.networkId,
    MIDNIGHT_NODE_URL: request.config.nodeUrl,
    MIDNIGHT_NODE_INDEXER_URL: request.config.indexerUrl,
    MIDNIGHT_NODE_INDEXER_WS_URL: request.config.indexerWsUrl,
    MIDNIGHT_NODE_PROOF_SERVER_URL: request.config.proofServerUrl,
    DEPLOYER_SEED,
    USER_SEED,
    MPC_SECP256K1_PUBKEY: request.mpcPublicKey,
    MAINTENANCE_SIGNING_KEY: randomBytes(32).toString("hex"),
    ERC20_ADDRESS: SEPOLIA_USDC,
    EVM_CHAIN_ID: "31337",
  };
  await fundRoles(request.config);
  const central = await deploySignetContract(env);
  env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS = central.contractAddress;
  const vault = await deployVault(env);
  env.MIDNIGHT_VAULT_CONTRACT_ADDRESS = vault.contractAddress;
  active = {
    env,
    artifactDir: request.artifactDir,
    vaultAddress: vault.contractAddress,
    mpcPublicKey: request.mpcPublicKey,
    operations: [],
  };
  await persist(active);
  return {
    centralAddress: central.contractAddress,
    callerAddress: vault.contractAddress,
    publisherSeed: PUBLISHER_SEED,
  };
}

// Capture the exact public finalized transaction at the provider boundary. No
// private state, wallet keys or unproven witness material is serialized here.
async function captureSubmissions(session: ActiveSession, context: VaultContext): Promise<void> {
  const directory = join(session.artifactDir, "transactions");
  await mkdir(directory, { recursive: true });
  const submit = context.providers.midnightProvider.submitTx.bind(
    context.providers.midnightProvider,
  );
  let sequence = 0;
  context.providers.midnightProvider.submitTx = async (transaction) => {
    sequence += 1;
    assert(sequence <= 32, "unexpectedly many vault submissions");
    const stem = join(directory, String(sequence).padStart(2, "0"));
    const calls = [...(transaction.intents?.entries() ?? [])].flatMap(([segment, intent]) =>
      intent.actions.flatMap((action) =>
        "guaranteedTranscript" in action
          ? [
              {
                segment,
                address: action.address,
                entryPoint:
                  typeof action.entryPoint === "string"
                    ? action.entryPoint
                    : Buffer.from(action.entryPoint).toString("hex"),
                singleton: action.address === context.signetContractAddress,
                guaranteed: action.guaranteedTranscript !== undefined,
                fallible: action.fallibleTranscript !== undefined,
              },
            ]
          : [],
      ),
    );
    const evidence = {
      sequence,
      operation: session.current?.operation,
      phase: session.current?.phase,
      transactionHash: transaction.transactionHash(),
      identifiers: transaction.identifiers(),
      calls,
    };
    await writeFile(`${stem}.bin`, transaction.serialize());
    await writeFile(`${stem}.json`, JSON.stringify(evidence, null, 2));
    const submittedId = await submit(transaction);
    await writeFile(`${stem}.json`, JSON.stringify({ ...evidence, submittedId }, null, 2));
    return submittedId;
  };
}

async function runVault(
  session: ActiveSession,
  evmRpcUrl: string,
): Promise<{ operations: OperationEvidence[] }> {
  assert(session.responsePublicKey, "initialise must provide the real MPC response key");
  assert.equal(session.vaultSession, undefined, "runVault may only run once");
  const endpoint = new URL(evmRpcUrl);
  assert(
    ["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname),
    "EVM funding requires a local endpoint",
  );
  assert(await isAnvil(evmRpcUrl), "EVM funding requires Anvil");
  const provider = new JsonRpcProvider(evmRpcUrl);
  try {
    assert.equal((await provider.getNetwork()).chainId, 31337n);
  } finally {
    provider.destroy();
  }
  session.env.EVM_RPC_URL = evmRpcUrl;
  session.env.MPC_RESPONSE_KEY = session.responsePublicKey;
  const config = await resolveInitialiseConfig(session.env, session.vaultAddress);
  session.env.EVM_VAULT_ADDRESS = config.vaultEvmAddress;
  session.env.EVM_USER_ADDRESS = deriveEvmAddress(
    session.mpcPublicKey,
    session.vaultAddress,
    resolveUserIdentity(session.env).commitmentHex,
  );
  await initialiseVault(session.env, session.vaultAddress);
  await dealForkEvmAccounts(session.env);
  const vaultSession = createVaultSession(session.env);
  session.vaultSession = vaultSession;
  const context = await vaultSession.vaultContext();
  await captureSubmissions(session, context);
  const readLedger = () =>
    readVaultLedger(context.providers.publicDataProvider, context.vaultContractAddress);
  const initial = await readLedger();
  assert.equal(initial.initialised, 1n);
  assert.equal(initial.evmChainId, 31337n);
  assert.deepEqual(initial.mpcResponseKey, parseSecp256k1PublicKey(session.responsePublicKey));

  const amount = 100_000n;
  await attempt(session, Operation.Deposit, [], async () => {
    await deposit(session, vaultSession, Operation.Deposit, amount);
  });
  await attempt(session, Operation.Withdraw, [Operation.Deposit], async () => {
    const beforeWithdraw = await getErc20Balance(evmRpcUrl, SEPOLIA_USDC, context.evmUserAddress);
    const shieldedBeforeWithdraw = await balance(vaultSession, SEPOLIA_USDC, session.vaultAddress);
    const withdrawNonce = await getTransactionNonce(evmRpcUrl, context.evmVaultAddress);
    const withdrawal = await begin(session, Operation.Withdraw, () =>
      startWithdraw(context, {
        amount,
        destEvmAddress: context.evmUserAddress,
        evmNonce: withdrawNonce,
      }),
    );
    await broadcast(session, context, withdrawal, VAULT_REQUESTS_PATH);
    const withdrawOutcome = await pollRespondBidirectional(context, {
      requestId: withdrawal,
      timeoutMs: 180_000,
      intervalMs: 1000,
    });
    assert(withdrawOutcome.succeeded);
    await phase(session, Phase.Attested);
    await settleWithdraw(context, withdrawal, withdrawOutcome);
    const withdrawn = await readLedger();
    assert.equal(withdrawn.signBidirectionalEventMap.member(requestIdBytes(withdrawal)), false);
    assert.equal(withdrawn.withdrawSettleViews.member(requestIdBytes(withdrawal)), false);
    assert.equal(
      (await getErc20Balance(evmRpcUrl, SEPOLIA_USDC, context.evmUserAddress)).balance -
        beforeWithdraw.balance,
      amount,
    );
    assert.equal(
      shieldedBeforeWithdraw - (await balance(vaultSession, SEPOLIA_USDC, session.vaultAddress)),
      amount,
    );
    await phase(session, Phase.Complete);
  });

  const tokenOut = "0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4";
  const fee = 500n;
  const amountOut = 1_000_000n;
  let amountInMaximum: bigint | undefined;
  await attempt(session, Operation.DepositSwap, [], async () => {
    ({ amountInMaximum } = await quoteExactOutputSingle(
      evmRpcUrl,
      SEPOLIA_USDC,
      tokenOut,
      fee,
      amountOut,
      1000n,
    ));
    await deposit(session, vaultSession, Operation.DepositSwap, amountInMaximum);
  });
  await attempt(session, Operation.ApproveRouter, [], async () => {
    const routerNonce = await getTransactionNonce(evmRpcUrl, context.evmVaultAddress);
    const routerApproval = await begin(session, Operation.ApproveRouter, () =>
      approveRouter(context, routerNonce),
    );
    await broadcast(session, context, routerApproval, VAULT_REQUESTS_PATH);
    assert(
      (
        await pollRespondBidirectional(context, {
          requestId: routerApproval,
          timeoutMs: 180_000,
          intervalMs: 1000,
        })
      ).succeeded,
    );
    await phase(session, Phase.Complete);
  });
  await attempt(
    session,
    Operation.Swap,
    [Operation.DepositSwap, Operation.ApproveRouter],
    async () => {
      const maximum = amountInMaximum;
      assert(maximum !== undefined, "swap deposit did not establish the quoted maximum");
      const outBefore = await balance(vaultSession, tokenOut, session.vaultAddress);
      const inBefore = await balance(vaultSession, SEPOLIA_USDC, session.vaultAddress);
      const swapNonce = await getTransactionNonce(evmRpcUrl, context.evmVaultAddress);
      const swap = await begin(session, Operation.Swap, () =>
        startSwap(context, {
          tokenOut,
          fee,
          amountOut,
          amountInMaximum: maximum,
          evmNonce: swapNonce,
        }),
      );
      await broadcast(session, context, swap, VAULT_SWAP_REQUESTS_PATH);
      const swapResult = await completeSwap(context, swap);
      assert.equal(swapResult.refunded, false);
      assert(swapResult.amountIn > 0n && swapResult.amountIn < maximum);
      assert.equal(
        (await balance(vaultSession, tokenOut, session.vaultAddress)) - outBefore,
        amountOut,
      );
      assert.equal(
        inBefore - (await balance(vaultSession, SEPOLIA_USDC, session.vaultAddress)),
        swapResult.amountIn,
      );
      assert.equal((await readLedger()).swapEventMap.member(requestIdBytes(swap)), false);
      await phase(session, Phase.Complete);
    },
  );

  const supplyAmount = 1_000_000n;
  await attempt(session, Operation.DepositSupply, [], async () => {
    await deposit(session, vaultSession, Operation.DepositSupply, supplyAmount, AAVE_USDC);
  });
  await attempt(session, Operation.ApproveStata, [], async () => {
    const stataNonce = await getTransactionNonce(evmRpcUrl, context.evmVaultAddress);
    const stataApproval = await begin(session, Operation.ApproveStata, () =>
      approveStata(context, stataNonce),
    );
    await broadcast(session, context, stataApproval, VAULT_REQUESTS_PATH);
    assert(
      (
        await pollRespondBidirectional(context, {
          requestId: stataApproval,
          timeoutMs: 180_000,
          intervalMs: 1000,
        })
      ).succeeded,
    );
    await phase(session, Phase.Complete);
  });
  let suppliedShares: bigint | undefined;
  await attempt(
    session,
    Operation.Supply,
    [Operation.DepositSupply, Operation.ApproveStata],
    async () => {
      const stataBefore = await balance(vaultSession, STATA_USDC, session.vaultAddress);
      const supplyNonce = await getTransactionNonce(evmRpcUrl, context.evmVaultAddress);
      const supply = await begin(session, Operation.Supply, () =>
        startSupply(context, { amount: supplyAmount, evmNonce: supplyNonce }),
      );
      await broadcast(session, context, supply, VAULT_SUPPLY_REQUESTS_PATH);
      const supplyResult = await completeSupply(context, supply);
      assert.equal(supplyResult.refunded, false);
      assert(supplyResult.shares > 0n);
      assert.equal(
        (await balance(vaultSession, STATA_USDC, session.vaultAddress)) - stataBefore,
        supplyResult.shares,
      );
      assert.equal((await readLedger()).supplyEventMap.member(requestIdBytes(supply)), false);
      await phase(session, Phase.Complete);
      suppliedShares = supplyResult.shares;
    },
  );
  await attempt(session, Operation.Redeem, [Operation.Supply], async () => {
    const shares = suppliedShares;
    assert(shares !== undefined, "supply did not produce redeemable shares");
    const usdcBefore = await balance(vaultSession, AAVE_USDC, session.vaultAddress);
    const redeemNonce = await getTransactionNonce(evmRpcUrl, context.evmVaultAddress);
    const redeem = await begin(session, Operation.Redeem, () =>
      startRedeem(context, { shares, evmNonce: redeemNonce }),
    );
    await broadcast(session, context, redeem, VAULT_REDEEM_REQUESTS_PATH);
    const redeemResult = await completeRedeem(context, redeem);
    assert.equal(redeemResult.refunded, false);
    assert(redeemResult.assets > 0n);
    assert.equal(
      (await balance(vaultSession, AAVE_USDC, session.vaultAddress)) - usdcBefore,
      redeemResult.assets,
    );
    assert.equal((await readLedger()).redeemEventMap.member(requestIdBytes(redeem)), false);
    await phase(session, Phase.Complete);
  });
  return { operations: session.operations };
}

async function dispatch(request: Request): Promise<object> {
  if (request.op === Command.Bootstrap) return bootstrap(request);
  if (request.op === Command.Shutdown) {
    await active?.vaultSession?.stop();
    active = undefined;
    return {};
  }
  assert(active, "driver is not bootstrapped");
  if (request.op === Command.Initialise) {
    assert.equal(active.responsePublicKey, undefined, "response key already provided");
    parseSecp256k1PublicKey(request.responsePublicKey);
    active.responsePublicKey = request.responsePublicKey;
    return {};
  }
  try {
    return await runVault(active, request.evmRpcUrl);
  } catch (error) {
    active.error = error instanceof Error ? (error.stack ?? error.message) : String(error);
    for (const operation of Object.values(Operation)) {
      if (!active.operations.some((entry) => entry.operation === operation))
        active.operations.push({
          operation,
          phase: Phase.Blocked,
          succeeded: false,
          error: `Vault setup or orchestration failed: ${active.error}`,
        });
    }
    await persist(active);
    return { operations: active.operations, error: active.error };
  }
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  try {
    const request = JSON.parse(line) as Request;
    const result = await dispatch(request);
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
    if (request.op === Command.Shutdown) break;
  } catch (error) {
    const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
    if (active) {
      active.error = message;
      if (active.current) {
        active.current.failedPhase = active.current.phase;
        active.current.error = message;
        await phase(active, Phase.Failed);
      }
      for (const operation of Object.values(Operation)) {
        if (!active.operations.some((entry) => entry.operation === operation))
          active.operations.push({ operation, phase: Phase.Blocked, succeeded: false });
      }
      await persist(active);
    }
    process.stdout.write(`${JSON.stringify({ ok: false, error: message })}\n`);
  }
}
await active?.vaultSession?.stop();
// SDK indexer providers keep websockets alive beyond their wallet lifecycle.
// All owned wallet work and evidence writes have completed at this boundary.
process.exit(0);
