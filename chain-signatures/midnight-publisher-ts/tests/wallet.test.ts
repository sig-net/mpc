import { afterEach, describe, expect, it, vi } from "vitest";

import type { FinalizedTransaction } from "@midnightntwrk/ledger-v9";
import { deriveAccountKeys, type WalletFacade } from "@sig-net/midnight-contract-deploy";
import { Subject } from "rxjs";

const sdk = vi.hoisted(() => ({ initialiseWalletFacade: vi.fn() }));

vi.mock("@sig-net/midnight-contract-deploy", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@sig-net/midnight-contract-deploy")>()),
  initialiseWalletFacade: sdk.initialiseWalletFacade,
}));

import { openFundingWallet } from "../src/wallet.js";
import { PublisherError } from "../src/errors.js";
import type { UnboundTransaction } from "../src/prover.js";
import type { BalancingRecipe } from "../src/wallet.js";

type UnboundRecipe = Awaited<ReturnType<WalletFacade["balanceUnboundTransaction"]>>;

const ENDPOINTS = {
  nodeUrl: "http://127.0.0.1:9944",
  proofServerUrl: "http://127.0.0.1:6300",
  indexerUrl: "http://127.0.0.1:8088/api/v3/graphql",
  indexerWsUrl: "ws://127.0.0.1:8088/api/v3/graphql/ws",
};
const KEYS = deriveAccountKeys("ab".repeat(32), "undeployed");

interface DustStateStub {
  readonly progress: {
    readonly isStrictlyComplete: () => boolean;
  };
}

function stubFacade(dustState = new Subject<DustStateStub>()) {
  return {
    start: vi.fn(async () => undefined),
    waitForSyncedState: vi.fn(async () => ({})),
    stop: vi.fn(async () => undefined),
    dust: { state: dustState },
    balanceUnboundTransaction: vi.fn(),
    signRecipe: vi.fn(),
    finalizeRecipe: vi.fn(),
    submitTransaction: vi.fn(async () => "ab".repeat(32)),
    submissionService: {
      submitTransaction: vi.fn(async () => ({ blockHash: `0x${"cd".repeat(32)}` })),
    },
    revert: vi.fn(async () => undefined),
  } as unknown as WalletFacade;
}

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("openFundingWallet", () => {
  it("starts once and opens while full-facade synchronization remains pending", async () => {
    vi.useFakeTimers();
    const facade = stubFacade();
    vi.mocked(facade.waitForSyncedState).mockReturnValueOnce(new Promise(() => undefined));
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);

    const opening = openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    const outcome = Promise.race([
      opening.then(() => "opened"),
      new Promise<"stalled">((resolve) => setTimeout(() => resolve("stalled"), 1)),
    ]);
    await vi.advanceTimersByTimeAsync(1);

    await expect(outcome).resolves.toBe("opened");
    expect(facade.start).toHaveBeenCalledExactlyOnceWith(
      KEYS.shieldedSecretKeys,
      KEYS.dustSecretKey,
    );
    expect(facade.waitForSyncedState).not.toHaveBeenCalled();
    expect(facade.stop).not.toHaveBeenCalled();
  });

  it("stops a facade whose startup fails partway through", async () => {
    const facade = stubFacade();
    vi.mocked(facade.start).mockRejectedValueOnce(new Error("dust wallet unavailable"));
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);

    await expect(openFundingWallet(KEYS, "undeployed", ENDPOINTS)).rejects.toThrow(
      "dust wallet unavailable",
    );

    expect(facade.start).toHaveBeenCalledOnce();
    expect(facade.waitForSyncedState).not.toHaveBeenCalled();
    expect(facade.stop).toHaveBeenCalledOnce();
  });

  it("cancels a timed-out DUST readiness wait without stopping and permits a later retry", async () => {
    vi.useFakeTimers();
    const dustState = new Subject<DustStateStub>();
    const facade = stubFacade(dustState);
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    const timeoutOutcome = wallet.requireReady(25).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(dustState.observed).toBe(true);
    await vi.advanceTimersByTimeAsync(25);

    const error = await timeoutOutcome;
    expect(error).toBeInstanceOf(PublisherError);
    expect(error).toMatchObject({
      code: "wallet_unsynced",
      message: expect.stringMatching(/DUST indexing is still catching up.*nothing was posted/i),
    });
    expect(dustState.observed).toBe(false);
    expect(facade.stop).not.toHaveBeenCalled();

    const incomplete = { progress: { isStrictlyComplete: vi.fn(() => false) } };
    const complete = { progress: { isStrictlyComplete: vi.fn(() => true) } };
    const retry = wallet.requireReady(100);
    dustState.next(incomplete);
    expect(incomplete.progress.isStrictlyComplete).toHaveBeenCalledOnce();
    expect(dustState.observed).toBe(true);
    dustState.next(complete);

    await expect(retry).resolves.toBeUndefined();
    expect(complete.progress.isStrictlyComplete).toHaveBeenCalledOnce();
    expect(dustState.observed).toBe(false);
    expect(facade.waitForSyncedState).not.toHaveBeenCalled();
    expect(facade.stop).not.toHaveBeenCalled();
  });

  it("submits through the facade so pending transaction state is tracked", async () => {
    const facade = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    const tx = { identifiers: () => ["ab".repeat(32)] } as unknown as FinalizedTransaction;

    expect(sdk.initialiseWalletFacade).toHaveBeenCalledWith(KEYS, {
      ...ENDPOINTS,
      networkId: "undeployed",
    });

    await expect(wallet.submitTx(tx)).resolves.toEqual({ txId: "ab".repeat(32) });

    expect(facade.submitTransaction).toHaveBeenCalledWith(tx);
    expect(facade.submissionService.submitTransaction).not.toHaveBeenCalled();
    await wallet.close();
    expect(facade.stop).toHaveBeenCalledOnce();
  });

  it("balances with wallet keys and a five-minute recipe before finalizing", async () => {
    const facade = stubFacade();
    const recipe = { recipe: true } as unknown as UnboundRecipe;
    const signed = { signed: true } as unknown as BalancingRecipe;
    const finalized = { finalized: true } as unknown as FinalizedTransaction;
    vi.mocked(facade.balanceUnboundTransaction).mockResolvedValueOnce(recipe);
    vi.mocked(facade.signRecipe).mockResolvedValueOnce(signed);
    vi.mocked(facade.finalizeRecipe).mockResolvedValueOnce(finalized);
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    const tx = { unbound: true } as unknown as UnboundTransaction;
    const before = Date.now();

    await expect(wallet.balanceTx(tx)).resolves.toBe(signed);
    const [, keys, options] = vi.mocked(facade.balanceUnboundTransaction).mock.calls[0]!;
    expect(keys).toMatchObject({
      shieldedSecretKeys: expect.anything(),
      dustSecretKey: expect.anything(),
    });
    expect(options.tokenKindsToBalance).toEqual(["dust"]);
    expect(options.ttl.getTime()).toBeGreaterThanOrEqual(before + 5 * 60 * 1_000);
    expect(options.ttl.getTime()).toBeLessThanOrEqual(Date.now() + 5 * 60 * 1_000);
    expect(facade.signRecipe).toHaveBeenCalledWith(recipe, expect.any(Function));
    await expect(wallet.finalizeTx(signed)).resolves.toBe(finalized);
  });

  it("does not submit a transaction with no identifier", async () => {
    const facade = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    const tx = { identifiers: () => [] } as unknown as FinalizedTransaction;

    await expect(wallet.submitTx(tx)).rejects.toThrow("carries no identifier");
    expect(facade.submitTransaction).not.toHaveBeenCalled();
  });
});
