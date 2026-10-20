import { afterEach, describe, expect, it, vi } from "vitest";

import type { FinalizedTransaction } from "@midnightntwrk/ledger-v9";
import { deriveAccountKeys, type WalletFacade } from "@sig-net/midnight-contract-deploy";
import { concat, of, Subject } from "rxjs";

const sdk = vi.hoisted(() => {
  // Every restored sub-wallet's `stop`, in restore order.
  const stops: ReturnType<typeof vi.fn>[] = [];
  const restored = (kind: string) =>
    vi.fn(() => ({
      restore: (state: string) => {
        // As the SDK's `restore` does on state it cannot decode.
        if (state === "corrupt") throw new Error("getOrThrow called on a Left");
        const stop = vi.fn(async () => undefined);
        stops.push(stop);
        return { kind, state, stop };
      },
    }));
  return { initialiseWalletFacade: vi.fn(), init: vi.fn(), restored, stops };
});

vi.mock("@sig-net/midnight-contract-deploy", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@sig-net/midnight-contract-deploy")>()),
  initialiseWalletFacade: sdk.initialiseWalletFacade,
}));

vi.mock("@midnightntwrk/wallet-sdk-facade", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@midnightntwrk/wallet-sdk-facade")>()),
  WalletFacade: { init: sdk.init },
}));
vi.mock("@midnightntwrk/wallet-sdk-shielded", () => ({ ShieldedWallet: sdk.restored("shielded") }));
vi.mock("@midnightntwrk/wallet-sdk-unshielded-wallet", () => ({
  UnshieldedWallet: sdk.restored("unshielded"),
}));
vi.mock("@midnightntwrk/wallet-sdk-dust-wallet", () => ({ DustWallet: sdk.restored("dust") }));

import { openFundingWallet } from "../src/wallet.js";
import { PublisherError } from "../src/errors.js";
import type { UnboundTransaction } from "../src/prover.js";
import { encodeSnapshot } from "../src/snapshot.js";
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

const syncProgress = (appliedIndex: bigint, highestIndex: bigint) => ({
  appliedIndex,
  highestIndex,
  isConnected: true,
});

// The fields of the facade's state this module reads, at values a summary tells apart.
function facadeState(isSynced: boolean) {
  return {
    isSynced,
    pending: { all: [] as unknown[] },
    shielded: { pendingCoins: [] as unknown[], progress: syncProgress(4n, 4n) },
    unshielded: {
      pendingCoins: [] as unknown[],
      progress: { appliedId: 2n, highestTransactionId: 3n, isConnected: false },
    },
    dust: {
      availableCoins: [{}, {}],
      pendingCoins: [] as unknown[],
      balance: () => 7n,
      progress: syncProgress(5n, 9n),
    },
  };
}

function stubFacade(dustState = new Subject<DustStateStub>(), isSynced = false) {
  return {
    start: vi.fn(async () => undefined),
    stop: vi.fn(async () => undefined),
    state: vi.fn(() => of(facadeState(isSynced))),
    shielded: { serializeState: vi.fn(async () => "shielded-state") },
    unshielded: { serializeState: vi.fn(async () => "unshielded-state") },
    dust: { state: dustState, serializeState: vi.fn(async () => "dust-state") },
    balanceUnboundTransaction: vi.fn(),
    signRecipe: vi.fn(),
    finalizeRecipe: vi.fn(),
    submitTransaction: vi.fn(async () => "ab".repeat(32)),
  } as unknown as WalletFacade;
}

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("openFundingWallet", () => {
  it("opens as soon as the facade has started, without waiting for it to sync", async () => {
    const facade = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);

    await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    expect(sdk.initialiseWalletFacade).toHaveBeenCalledWith(KEYS, {
      ...ENDPOINTS,
      networkId: "undeployed",
    });
    expect(facade.start).toHaveBeenCalledExactlyOnceWith(
      KEYS.shieldedSecretKeys,
      KEYS.dustSecretKey,
    );
    expect(facade.stop).not.toHaveBeenCalled();
  });

  it("stops a facade whose startup fails partway through", async () => {
    const facade = stubFacade();
    vi.mocked(facade.start).mockRejectedValueOnce(new Error("dust wallet unavailable"));
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);

    await expect(openFundingWallet(KEYS, "undeployed", ENDPOINTS)).rejects.toThrow(
      "dust wallet unavailable",
    );

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
    expect(facade.stop).not.toHaveBeenCalled();
  });

  it("submits through the facade, which tracks the pending transaction, and stops it on close", async () => {
    const facade = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    const tx = { identifiers: () => ["ab".repeat(32)] } as unknown as FinalizedTransaction;

    await expect(wallet.submitTx(tx)).resolves.toEqual({ txId: "ab".repeat(32) });
    await expect(
      wallet.submitTx({ identifiers: () => [] } as unknown as FinalizedTransaction),
    ).rejects.toThrow("carries no identifier");
    expect(facade.submitTransaction).toHaveBeenCalledExactlyOnceWith(tx);

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
});

describe("openFundingWallet with a snapshot", () => {
  const OWNER = KEYS.unshieldedKeystore.getBech32Address().asString();
  const STATES = { shielded: "s", unshielded: "u", dust: "d" };
  const SNAPSHOT = encodeSnapshot("undeployed", OWNER, STATES, new Date());

  it("restores every sub-wallet from the snapshot and starts it with the wallet's keys", async () => {
    const facade = stubFacade(new Subject(), true);
    sdk.init.mockResolvedValueOnce(facade);

    await openFundingWallet(KEYS, "undeployed", ENDPOINTS, SNAPSHOT);

    expect(sdk.initialiseWalletFacade).not.toHaveBeenCalled();
    const params = sdk.init.mock.calls[0]![0];
    expect(params.shielded({})).toMatchObject({ kind: "shielded", state: "s" });
    expect(params.unshielded({})).toMatchObject({ kind: "unshielded", state: "u" });
    expect(params.dust({})).toMatchObject({ kind: "dust", state: "d" });
    expect(params.configuration).toMatchObject({
      networkId: "undeployed",
      indexerClientConnection: {
        indexerHttpUrl: ENDPOINTS.indexerUrl,
        indexerWsUrl: ENDPOINTS.indexerWsUrl,
      },
      relayURL: new URL("ws://127.0.0.1:9944"),
      costParameters: { feeBlocksMargin: 5 },
    });
    expect(facade.start).toHaveBeenCalledExactlyOnceWith(
      KEYS.shieldedSecretKeys,
      KEYS.dustSecretKey,
    );
  });

  it("syncs from the start when the snapshot belongs elsewhere or does not decode", async () => {
    for (const snapshot of [
      encodeSnapshot("preview", OWNER, STATES, new Date()),
      encodeSnapshot("undeployed", "mn_addr_other", STATES, new Date()),
      "not json",
      JSON.stringify({ version: 2 }),
    ]) {
      const facade = stubFacade();
      sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);

      await openFundingWallet(KEYS, "undeployed", ENDPOINTS, snapshot);

      expect(sdk.init, snapshot).not.toHaveBeenCalled();
      expect(facade.start, snapshot).toHaveBeenCalledOnce();
      vi.clearAllMocks();
    }
  });

  it("syncs from the start without opening a facade when a state does not decode", async () => {
    // `init` opens the node connection before it builds the wallets, and could not close it.
    sdk.stops.length = 0;
    const fresh = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(fresh);

    await openFundingWallet(
      KEYS,
      "undeployed",
      ENDPOINTS,
      encodeSnapshot("undeployed", OWNER, { ...STATES, dust: "corrupt" }, new Date()),
    );

    expect(sdk.init).not.toHaveBeenCalled();
    expect(sdk.stops).toHaveLength(2);
    for (const stop of sdk.stops) expect(stop).toHaveBeenCalledOnce();
    expect(fresh.start).toHaveBeenCalledOnce();
  });

  it("syncs from the start when the restored wallet fails to start, stopping it first", async () => {
    const broken = stubFacade();
    vi.mocked(broken.start).mockRejectedValueOnce(new Error("corrupt state"));
    sdk.init.mockResolvedValueOnce(broken);
    const fresh = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(fresh);

    await openFundingWallet(KEYS, "undeployed", ENDPOINTS, SNAPSHOT);

    expect(broken.stop).toHaveBeenCalledOnce();
    expect(fresh.start).toHaveBeenCalledOnce();
    expect(fresh.stop).not.toHaveBeenCalled();
  });

  it("syncs from the start when the restored wallet does not catch up within three minutes", async () => {
    vi.useFakeTimers();
    const stuck = stubFacade();
    const behind = new Subject<ReturnType<typeof facadeState>>();
    vi.mocked(stuck.state).mockReturnValue(behind as never);
    sdk.init.mockResolvedValueOnce(stuck);
    const fresh = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(fresh);

    const opening = openFundingWallet(KEYS, "undeployed", ENDPOINTS, SNAPSHOT);
    // A stuck restore still reports progress, just never a synced state.
    for (let second = 0; second < 179; second += 1) {
      behind.next(facadeState(false));
      await vi.advanceTimersByTimeAsync(1_000);
    }
    expect(stuck.stop).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1_000);
    await opening;

    expect(stuck.stop).toHaveBeenCalledOnce();
    expect(fresh.start).toHaveBeenCalledOnce();
  });

  it("snapshots only a fully synced wallet, as this wallet's states on this network", async () => {
    const syncing = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(syncing);
    await expect(
      (await openFundingWallet(KEYS, "undeployed", ENDPOINTS)).snapshot(),
    ).rejects.toMatchObject({ code: "wallet_unsynced" });
    expect(syncing.dust.serializeState).not.toHaveBeenCalled();

    sdk.initialiseWalletFacade.mockResolvedValueOnce(stubFacade(new Subject(), true));
    const snapshot = await (await openFundingWallet(KEYS, "undeployed", ENDPOINTS)).snapshot();
    expect(JSON.parse(snapshot!)).toEqual({
      version: 1,
      networkId: "undeployed",
      owner: OWNER,
      takenAt: expect.any(Number),
      shielded: "shielded-state",
      unshielded: "unshielded-state",
      dust: "dust-state",
    });
  });

  it("refuses to snapshot until every submitted transaction has a result, so a restore starts clean", async () => {
    for (const unsettled of ["shielded", "unshielded", "dust", "pending"] as const) {
      const busy = stubFacade(new Subject(), true);
      const state = facadeState(true);
      if (unsettled === "pending") state.pending.all = [{ tx: "submitted" }];
      else state[unsettled].pendingCoins = [{ coin: unsettled }];
      vi.mocked(busy.state).mockReturnValue(of(state) as never);
      sdk.initialiseWalletFacade.mockResolvedValueOnce(busy);

      await expect(
        (await openFundingWallet(KEYS, "undeployed", ENDPOINTS)).snapshot(),
        unsettled,
      ).rejects.toMatchObject({ code: "wallet_busy" });
      expect(busy.dust.serializeState, unsettled).not.toHaveBeenCalled();
    }
  });

  it("waits a few seconds for the transaction a submit just returned for to settle", async () => {
    vi.useFakeTimers();
    const inFlight = facadeState(true);
    inFlight.pending.all = [{ tx: "submitted" }];
    const confirmed = new Subject<ReturnType<typeof facadeState>>();
    const facade = stubFacade(new Subject(), true);
    vi.mocked(facade.state).mockImplementation(() => concat(of(inFlight), confirmed) as never);
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    const snapshot = wallet.snapshot();
    await vi.advanceTimersByTimeAsync(4_000);
    confirmed.next(facadeState(true));
    expect(JSON.parse((await snapshot)!)).toMatchObject({ dust: "dust-state" });

    const stuck = wallet.snapshot().catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await stuck).toMatchObject({ code: "wallet_busy" });
  });

  it("summarises the wallet's coins and sync on one line, or why it cannot", async () => {
    sdk.initialiseWalletFacade.mockResolvedValueOnce(stubFacade());
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    expect(await wallet.describe()).toBe(
      "synced=false pendingTxs=0 " +
        "dust(spendable=2 inFlight=0 specks=7 applied=5/9 connected=true) " +
        "shielded(inFlight=0 applied=4/4 connected=true) " +
        "unshielded(inFlight=0 applied=2/3 connected=false)",
    );

    vi.useFakeTimers();
    const silent = stubFacade();
    vi.mocked(silent.state).mockReturnValue(new Subject() as never);
    sdk.initialiseWalletFacade.mockResolvedValueOnce(silent);
    const described = (await openFundingWallet(KEYS, "undeployed", ENDPOINTS)).describe();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await described).toMatch(/^unavailable \(/);
  });
});
