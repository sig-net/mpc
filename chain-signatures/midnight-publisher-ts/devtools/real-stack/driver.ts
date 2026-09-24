import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { rawTokenType } from "@midnight-ntwrk/compact-runtime";
import { findDeployedContract } from "@midnight-ntwrk/midnight-js/contracts";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  asciiPadded,
  bytesToHex,
  calculateRequestId,
  deriveEvmAddress,
  deriveMidnightResponseKey,
  deserializeEvmOutput,
  hexToBytes,
  parseSecp256k1PublicKey,
  requestIdBytes,
  requestIdHex,
  respondBidirectionalEventToCircuitInput,
  serializeRespondOutput,
  SIGNET_DEFAULT_KEY_VERSION,
  signetEventSourceFromPublicDataProvider,
  SignetRequestResponseReader,
  toSignBidirectionalEventIndex,
  type RequestIdHex,
  type Secp256k1Point,
} from "@sig-net/midnight";
import {
  deploySignetContract,
  deriveAccountKeys,
  withSyncedWalletFacade,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import { JsonRpcProvider } from "ethers";
import { deployVault } from "./deploy.js";
import {
  AAVE_USDC,
  erc20Balance,
  fundFork,
  quoteSwap,
  SEPOLIA_USDC,
  STATA_USDC,
  UNISWAP_ROUTER,
} from "./evm.js";
import { DEPLOYER_SEED, fundRoles, PUBLISHER_SEED, USER_SEED } from "./funding.js";
import { ledger, pureCircuits } from "./managed/erc20-vault/contract/index.js";
import {
  buildProviders,
  vaultCompiledContract,
  vaultManagedPath,
  VAULT_PRIVATE_STATE_ID,
} from "./providers.js";
import { createPrivateState } from "./witnesses.js";

type Request =
  | { op: "bootstrap"; config: MidnightNodeConfig; artifactDir: string; mpcPublicKey: string }
  | { op: "initialise"; responsePublicKey: string }
  | { op: "runVault"; evmRpcUrl: string }
  | { op: "shutdown" };

interface Session {
  config: MidnightNodeConfig;
  artifactDir: string;
  centralAddress: string;
  vaultAddress: string;
  mpcPublicKey: string;
  responseKey?: Secp256k1Point;
}

interface OperationResult {
  operation: string;
  requestId: RequestIdHex;
  succeeded: boolean;
}

// These paths also occur in the contract's MPC notifications. Check the compiler
// layout before deploying so a changed ledger cannot silently redirect a reader.
const requestPaths = {
  signBidirectionalEventMap: [0, 0],
  depositEventMap: [1, 3],
  swapEventMap: [1, 7],
  supplyEventMap: [1, 11],
  redeemEventMap: [1, 13],
} as const;
type RequestMap = keyof typeof requestPaths;

let session: Session | undefined;
const diagnostics = (...values: unknown[]) => {
  process.stderr.write(`${values.map(String).join(" ")}\n`);
};
console.log = diagnostics;
console.info = diagnostics;
console.warn = diagnostics;

async function waitFor<T>(description: string, read: () => Promise<T | undefined>): Promise<T> {
  const deadline = Date.now() + 360_000;
  while (Date.now() < deadline) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`timed out waiting for ${description}`);
}

async function bootstrap(request: Extract<Request, { op: "bootstrap" }>) {
  assert.equal(session, undefined, "driver is already bootstrapped");
  assert.equal(request.config.networkId, "undeployed", "funding requires the local stack");
  parseSecp256k1PublicKey(request.mpcPublicKey);
  const info = JSON.parse(
    await readFile(join(vaultManagedPath, "compiler/contract-info.json"), "utf8"),
  ) as { ledger: { name: string; index: number[] }[] };
  for (const [name, expected] of Object.entries({ ...requestPaths, signetRequestNonce: [0, 3] })) {
    assert.deepEqual(info.ledger.find((field) => field.name === name)?.index, expected, name);
  }
  await mkdir(request.artifactDir, { recursive: true });
  process.chdir(request.artifactDir);
  setNetworkId(request.config.networkId);
  await fundRoles(request.config);
  const central = await deploySignetContract({
    NETWORK_ID: request.config.networkId,
    MIDNIGHT_NODE_URL: request.config.nodeUrl,
    MIDNIGHT_NODE_INDEXER_URL: request.config.indexerUrl,
    MIDNIGHT_NODE_INDEXER_WS_URL: request.config.indexerWsUrl,
    MIDNIGHT_NODE_PROOF_SERVER_URL: request.config.proofServerUrl,
    DEPLOYER_SEED,
  });
  const vaultAddress = await deployVault(request.config, central.contractAddress);
  session = {
    config: request.config,
    artifactDir: request.artifactDir,
    mpcPublicKey: request.mpcPublicKey,
    centralAddress: central.contractAddress,
    vaultAddress,
  };
  return {
    centralAddress: central.contractAddress,
    callerAddress: vaultAddress,
    publisherSeed: PUBLISHER_SEED,
  };
}

function evmVaultAddress(active: Session): string {
  return deriveEvmAddress(
    active.mpcPublicKey,
    active.vaultAddress,
    bytesToHex(asciiPadded("vault", 32)),
  );
}

async function initialise(active: Session, responsePublicKey: string): Promise<void> {
  assert.equal(active.responseKey, undefined, "vault is already initialised");
  const responseKey = parseSecp256k1PublicKey(responsePublicKey);
  assert.deepEqual(
    responseKey,
    deriveMidnightResponseKey(active.mpcPublicKey, active.vaultAddress),
  );
  const keys = deriveAccountKeys(DEPLOYER_SEED, active.config.networkId);
  await withSyncedWalletFacade(keys, active.config, async (facade) => {
    const providers = buildProviders(
      facade,
      keys,
      active.config,
      join(active.artifactDir, "deployer.leveldb"),
    );
    const vault = await findDeployedContract(providers, {
      contractAddress: active.vaultAddress,
      compiledContract: vaultCompiledContract,
      privateStateId: VAULT_PRIVATE_STATE_ID,
      initialPrivateState: createPrivateState(hexToBytes(DEPLOYER_SEED)),
    });
    await vault.callTx.initialise(
      hexToBytes(evmVaultAddress(active)),
      hexToBytes(UNISWAP_ROUTER),
      hexToBytes(AAVE_USDC),
      hexToBytes(STATA_USDC),
      31337n,
      responseKey,
    );
    const state = await providers.publicDataProvider.queryContractState(active.vaultAddress);
    assert(state);
    const configured = ledger(state.data);
    assert.equal(configured.initialised, 1n);
    assert.equal(configured.evmChainId, 31337n);
    assert.deepEqual(configured.mpcResponseKey, responseKey);
  });
  active.responseKey = responseKey;
}

async function runVault(
  active: Session,
  evmRpcUrl: string,
): Promise<{ operations: OperationResult[] }> {
  assert(active.responseKey, "vault is not initialised");
  const responseKey = active.responseKey;
  const evm = new JsonRpcProvider(evmRpcUrl, undefined, { cacheTimeout: -1 });
  const evmVault = evmVaultAddress(active);
  const secretKey = hexToBytes(USER_SEED);
  const evmUser = deriveEvmAddress(
    active.mpcPublicKey,
    active.vaultAddress,
    bytesToHex(pureCircuits.userCommitment(secretKey)),
  );
  try {
    await fundFork(evm, evmRpcUrl, evmUser, evmVault);
    const keys = deriveAccountKeys(USER_SEED, active.config.networkId);
    return await withSyncedWalletFacade(keys, active.config, async (facade) => {
      const providers = buildProviders(
        facade,
        keys,
        active.config,
        join(active.artifactDir, "user.leveldb"),
      );
      const vault = await findDeployedContract(providers, {
        contractAddress: active.vaultAddress,
        compiledContract: vaultCompiledContract,
        privateStateId: VAULT_PRIVATE_STATE_ID,
        initialPrivateState: createPrivateState(secretKey),
      });
      const operations: OperationResult[] = [];
      const readLedger = async () => {
        const state = await providers.publicDataProvider.queryContractState(active.vaultAddress);
        assert(state, "vault state is missing");
        return ledger(state.data);
      };
      const tokenType = (token: string) =>
        rawTokenType(
          pureCircuits.vaultTokenDomainSeparator(hexToBytes(token)),
          active.vaultAddress,
        );
      const balance = async (token: string) =>
        (await facade.waitForSyncedState()).shielded.balances[tokenType(token)] ?? 0n;
      const coin = (token: string, amount: bigint) => ({
        nonce: randomBytes(32),
        color: hexToBytes(tokenType(token)),
        value: amount,
      });
      const nonce = async (address = evmVault) => BigInt(await evm.getTransactionCount(address));
      const removed = async (map: RequestMap, id: RequestIdHex) => {
        assert.equal(
          (await readLedger())[map].member(requestIdBytes(id)),
          false,
          `${map} must settle ${id}`,
        );
      };

      async function execute(
        operation: string,
        map: RequestMap,
        start: () => Promise<unknown>,
        signer = evmVault,
      ) {
        diagnostics(`starting ${operation}`);
        const before = toSignBidirectionalEventIndex((await readLedger())[map]);
        await start();
        const after = toSignBidirectionalEventIndex((await readLedger())[map]);
        const added = [...after].filter(([id]) => !before.has(id));
        assert.equal(added.length, 1, `${operation} must create exactly one request`);
        const entry = added[0];
        assert(entry);
        const [id, record] = entry;
        assert.equal(requestIdHex(calculateRequestId(record)), id);
        const result = { operation, requestId: id, succeeded: false };
        operations.push(result);
        const reader = new SignetRequestResponseReader({
          requesterContractAddress: active.vaultAddress,
          requesterRequestsPath: requestPaths[map],
          signetContractAddress: active.centralAddress,
          publicDataProvider: providers.publicDataProvider,
          eventSource: signetEventSourceFromPublicDataProvider(providers.publicDataProvider),
        });
        const signed = await waitFor(`${operation} signature`, () =>
          reader.getSignedEvmTransaction(id, signer),
        );
        const sent = await evm.broadcastTransaction(signed.serialized);
        const receipt = await sent.wait(1, 180_000);
        assert(receipt);
        assert.equal(receipt.status, 1, `${operation} EVM transaction failed`);
        const trace = (await evm.send("debug_traceTransaction", [
          receipt.hash,
          { tracer: "callTracer" },
        ])) as { output?: string };
        assert(typeof trace.output === "string", "Anvil trace must contain the executed output");
        const decoded = deserializeEvmOutput(record.outputDeserializationSchema, trace.output);
        if ("success" in decoded)
          assert.equal(decoded.success, true, `${operation} returned false`);
        const output = serializeRespondOutput(record.respondSerializationSchema, decoded);
        const response = await waitFor(`${operation} attestation`, () =>
          reader.getVerifiedRespondBidirectionalEvent(id, output, responseKey),
        );
        diagnostics(`attested ${operation}: ${id}`);
        return {
          id,
          output,
          decoded,
          response: respondBidirectionalEventToCircuitInput(response),
          result,
        };
      }

      async function deposit(operation: string, token: string, amount: bigint): Promise<void> {
        const before = await balance(token);
        const evmBefore = await erc20Balance(evm, token, evmVault);
        const depositNonce = await nonce(evmUser);
        const request = await execute(
          operation,
          "depositEventMap",
          () =>
            vault.callTx.startDeposit(
              depositNonce,
              100_000n,
              30_000_000_000n,
              1_000_000_000n,
              SIGNET_DEFAULT_KEY_VERSION,
              { erc20Address: hexToBytes(token), amount },
            ),
          evmUser,
        );
        await vault.callTx.completeDeposit(
          requestIdBytes(request.id),
          request.response,
          request.output,
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
        await removed("depositEventMap", request.id);
        assert.equal((await balance(token)) - before, amount);
        assert.equal((await erc20Balance(evm, token, evmVault)) - evmBefore, amount);
        request.result.succeeded = true;
      }

      const amount = 100_000n;
      await deposit("deposit", SEPOLIA_USDC, amount);
      const evmBefore = await erc20Balance(evm, SEPOLIA_USDC, evmUser);
      const beforeWithdraw = await balance(SEPOLIA_USDC);
      const withdrawNonce = await nonce();
      const withdraw = await execute("withdraw", "signBidirectionalEventMap", () =>
        vault.callTx.startWithdraw(
          withdrawNonce,
          SIGNET_DEFAULT_KEY_VERSION,
          { erc20Address: hexToBytes(SEPOLIA_USDC), amount, destEvmAddress: hexToBytes(evmUser) },
          coin(SEPOLIA_USDC, amount),
        ),
      );
      await vault.callTx.completeWithdraw(
        requestIdBytes(withdraw.id),
        withdraw.response,
        withdraw.output,
        randomBytes(32),
      );
      await removed("signBidirectionalEventMap", withdraw.id);
      assert.equal(
        (await readLedger()).withdrawSettleViews.member(requestIdBytes(withdraw.id)),
        false,
      );
      assert.equal((await erc20Balance(evm, SEPOLIA_USDC, evmUser)) - evmBefore, amount);
      assert.equal(beforeWithdraw - (await balance(SEPOLIA_USDC)), amount);
      withdraw.result.succeeded = true;

      const tokenOut = "0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4";
      const fee = 500n;
      const amountOut = 1_000_000n;
      const maximum = await quoteSwap(evm, tokenOut, fee, amountOut);
      await deposit("depositSwap", SEPOLIA_USDC, maximum);
      const routerNonce = await nonce();
      const router = await execute("approveRouter", "signBidirectionalEventMap", () =>
        vault.callTx.approveRouter(
          hexToBytes(SEPOLIA_USDC),
          routerNonce,
          SIGNET_DEFAULT_KEY_VERSION,
        ),
      );
      router.result.succeeded = true;
      const inputBefore = await balance(SEPOLIA_USDC);
      const outputBefore = await balance(tokenOut);
      const swapNonce = await nonce();
      const swap = await execute("swap", "swapEventMap", () =>
        vault.callTx.startSwap(
          swapNonce,
          SIGNET_DEFAULT_KEY_VERSION,
          {
            tokenIn: hexToBytes(SEPOLIA_USDC),
            tokenOut: hexToBytes(tokenOut),
            fee,
            amountOut,
            amountInMaximum: maximum,
          },
          coin(SEPOLIA_USDC, maximum),
        ),
      );
      const spent = swap.decoded.amountIn;
      assert(typeof spent === "bigint" && spent > 0n && spent < maximum);
      await vault.callTx.completeSwap(
        requestIdBytes(swap.id),
        swap.response,
        swap.output,
        randomBytes(32),
        randomBytes(32),
      );
      await removed("swapEventMap", swap.id);
      assert.equal((await balance(tokenOut)) - outputBefore, amountOut);
      assert.equal(inputBefore - (await balance(SEPOLIA_USDC)), spent);
      swap.result.succeeded = true;

      const supplyAmount = 1_000_000n;
      await deposit("depositSupply", AAVE_USDC, supplyAmount);
      const stataNonce = await nonce();
      const stata = await execute("approveStata", "signBidirectionalEventMap", () =>
        vault.callTx.approveStata(stataNonce, SIGNET_DEFAULT_KEY_VERSION),
      );
      stata.result.succeeded = true;
      const sharesBefore = await balance(STATA_USDC);
      const supplyNonce = await nonce();
      const supply = await execute("supply", "supplyEventMap", () =>
        vault.callTx.startSupply(
          supplyNonce,
          SIGNET_DEFAULT_KEY_VERSION,
          supplyAmount,
          coin(AAVE_USDC, supplyAmount),
        ),
      );
      const shares = supply.decoded.shares;
      assert(typeof shares === "bigint" && shares > 0n);
      await vault.callTx.completeSupply(
        requestIdBytes(supply.id),
        supply.response,
        supply.output,
        randomBytes(32),
      );
      await removed("supplyEventMap", supply.id);
      assert.equal((await balance(STATA_USDC)) - sharesBefore, shares);
      supply.result.succeeded = true;

      const assetsBefore = await balance(AAVE_USDC);
      const redeemNonce = await nonce();
      const redeem = await execute("redeem", "redeemEventMap", () =>
        vault.callTx.startRedeem(
          redeemNonce,
          SIGNET_DEFAULT_KEY_VERSION,
          shares,
          coin(STATA_USDC, shares),
        ),
      );
      const assets = redeem.decoded.assets;
      assert(typeof assets === "bigint" && assets > 0n);
      await vault.callTx.completeRedeem(
        requestIdBytes(redeem.id),
        redeem.response,
        redeem.output,
        randomBytes(32),
      );
      await removed("redeemEventMap", redeem.id);
      assert.equal((await balance(AAVE_USDC)) - assetsBefore, assets);
      redeem.result.succeeded = true;
      return { operations };
    });
  } finally {
    evm.destroy();
  }
}

async function dispatch(request: Request): Promise<unknown> {
  if (request.op === "bootstrap") return bootstrap(request);
  if (request.op === "shutdown") return {};
  assert(session, "driver is not bootstrapped");
  if (request.op === "initialise") {
    await initialise(session, request.responsePublicKey);
    return {};
  }
  return runVault(session, request.evmRpcUrl);
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  try {
    const request = JSON.parse(line) as Request;
    const result = await dispatch(request);
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
    if (request.op === "shutdown") break;
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({ ok: false, error: error instanceof Error ? (error.stack ?? error.message) : String(error) })}\n`,
    );
  }
}
// Indexer provider sockets outlive the wallet facades, which have all stopped.
process.exit(0);
