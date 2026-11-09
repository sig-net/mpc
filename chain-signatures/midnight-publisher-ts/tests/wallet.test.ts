import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FinalizedTransaction } from "@midnightntwrk/ledger-v9";
import { deriveAccountKeys, type WalletFacade } from "@sig-net/midnight-contract-deploy";
import { BehaviorSubject, concat, of, Subject } from "rxjs";

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

const probe = vi.hoisted(() => ({ latestDustEventId: vi.fn() }));
vi.mock("../src/dust-probe.js", () => probe);

// The node's own account of a submitted transaction; silent unless a test scripts it.
const landing = vi.hoisted(() => ({
  verdicts: [] as Promise<string>[],
  nodeRpc: vi.fn((url: string) => url),
  watchLanding: vi.fn(),
}));
vi.mock("../src/landing.js", () => landing);

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
  readonly balance?: (time: Date) => bigint;
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

beforeEach(() => {
  landing.watchLanding.mockImplementation(() => ({
    verdict: landing.verdicts.shift() ?? new Promise<string>(() => undefined),
    stop: vi.fn(),
  }));
});

const stubTx = () =>
  ({
    identifiers: () => ["ab".repeat(32)],
    serialize: () => Uint8Array.of(0xc0, 0xff, 0xee),
  }) as unknown as FinalizedTransaction;

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// The indexer probe's answer: `ok` from a live indexer, a rejected fetch from a dead one.
function stubIndexer(answers: () => boolean) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      if (!answers()) throw new TypeError("fetch failed");
      return { ok: true };
    }),
  );
}

// A restore still behind, at `applied` on the dust wallet.
function behindAt(applied: number) {
  const state = facadeState(false);
  return { ...state, dust: { ...state.dust, progress: syncProgress(BigInt(applied), 1_000n) } };
}

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

  it("reads the DUST balance only from a synced wallet", async () => {
    const dustState = new BehaviorSubject<DustStateStub>({
      progress: { isStrictlyComplete: () => false },
      balance: () => 7n,
    });
    sdk.initialiseWalletFacade.mockResolvedValueOnce(stubFacade(dustState));
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    await expect(wallet.dustBalance()).resolves.toBeUndefined();

    dustState.next({ progress: { isStrictlyComplete: () => true }, balance: () => 4_210n });
    await expect(wallet.dustBalance()).resolves.toBe(4_210n);
  });

  it("gives up on a DUST balance the wallet state never emits", async () => {
    vi.useFakeTimers();
    const dustState = new Subject<DustStateStub>();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(stubFacade(dustState));
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    const balance = wallet.dustBalance();
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(balance).resolves.toBeUndefined();
    expect(dustState.observed).toBe(false);
  });

  it("submits through the facade, which tracks the pending transaction, and stops it on close", async () => {
    const facade = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    const tx = stubTx();

    await expect(wallet.submitTx(tx)).resolves.toEqual({ txId: "ab".repeat(32) });
    await expect(
      wallet.submitTx({ identifiers: () => [] } as unknown as FinalizedTransaction),
    ).rejects.toThrow("carries no identifier");
    expect(facade.submitTransaction).toHaveBeenCalledExactlyOnceWith(tx);
    // Watched on the node by the very bytes the SDK sends.
    expect(landing.watchLanding).toHaveBeenCalledExactlyOnceWith(
      ENDPOINTS.nodeUrl,
      "c0ffee",
      "ab".repeat(32),
    );
    expect(landing.watchLanding.mock.results[0]!.value.stop).toHaveBeenCalledOnce();

    await wallet.close();
    expect(facade.stop).toHaveBeenCalledOnce();
  });

  it("answers from the node when the SDK's subscription never does", async () => {
    vi.useFakeTimers();
    // Unsettled: the reopen below waits, so this test sees only the answers.
    const facade = stubFacade();
    vi.mocked(facade.submitTransaction).mockReturnValue(new Promise(() => undefined));
    sdk.initialiseWalletFacade.mockResolvedValue(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    landing.verdicts.push(Promise.resolve("ab".repeat(32)));
    const landed = wallet.submitTx(stubTx());
    await vi.advanceTimersByTimeAsync(2_000);
    await expect(landed).resolves.toEqual({ txId: "ab".repeat(32) });

    const notSubmitted = new PublisherError("not_submitted", "held nowhere");
    landing.verdicts.push(Promise.reject(notSubmitted));
    await expect(wallet.submitTx(stubTx())).rejects.toBe(notSubmitted);
  });

  it("reopens the wallet once settled when the SDK never answered, off the submit", async () => {
    vi.useFakeTimers();
    const dustAtFive = { progress: { appliedIndex: 5n, isStrictlyComplete: () => true } };
    const silent = stubFacade(new BehaviorSubject(dustAtFive) as never, true);
    vi.mocked(silent.submitTransaction).mockReturnValue(new Promise(() => undefined));
    sdk.initialiseWalletFacade.mockResolvedValue(silent);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    const reopened = stubFacade(new BehaviorSubject(dustAtFive) as never, true);
    sdk.init.mockResolvedValueOnce(reopened);
    probe.latestDustEventId.mockResolvedValue(5n);

    landing.verdicts.push(Promise.resolve("ab".repeat(32)));
    const landed = wallet.submitTx(stubTx());
    await vi.advanceTimersByTimeAsync(2_000);
    await expect(landed).resolves.toEqual({ txId: "ab".repeat(32) });
    // The next submit's check waits for the reopen rather than using the dead socket.
    await wallet.ensureCurrent(60_000);

    const resumed = sdk.init.mock.calls[0]![0];
    expect(resumed.dust({})).toMatchObject({ kind: "dust", state: "dust-state" });
    expect(silent.stop).toHaveBeenCalledOnce();
    await wallet.submitTx(stubTx());
    expect(reopened.submitTransaction).toHaveBeenCalledOnce();
  });

  it("keeps the wallet when the SDK answers within a moment of the node", async () => {
    vi.useFakeTimers();
    const facade = stubFacade(new BehaviorSubject({}) as never, true);
    let answer!: (txId: string) => void;
    vi.mocked(facade.submitTransaction).mockReturnValue(
      new Promise((resolve) => (answer = resolve)),
    );
    sdk.initialiseWalletFacade.mockResolvedValue(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    landing.verdicts.push(Promise.resolve("ab".repeat(32)));
    const landed = wallet.submitTx(stubTx());
    await vi.advanceTimersByTimeAsync(1_000);
    answer("ab".repeat(32));
    await vi.advanceTimersByTimeAsync(40_000);
    await landed;

    expect(sdk.init).not.toHaveBeenCalled();
    expect(facade.stop).not.toHaveBeenCalled();
  });

  it("does not reopen a wallet whose landed transaction never settles", async () => {
    vi.useFakeTimers();
    const facade = stubFacade(new BehaviorSubject({}) as never, false);
    vi.mocked(facade.submitTransaction).mockReturnValue(new Promise(() => undefined));
    sdk.initialiseWalletFacade.mockResolvedValue(facade);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);

    landing.verdicts.push(Promise.resolve("ab".repeat(32)));
    void wallet.submitTx(stubTx());
    await vi.advanceTimersByTimeAsync(2_000 + 30_000);

    expect(sdk.init).not.toHaveBeenCalled();
    expect(facade.stop).not.toHaveBeenCalled();
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

  it("syncs from the start after three minutes without progress against an answering indexer", async () => {
    vi.useFakeTimers();
    stubIndexer(() => true);
    const stuck = stubFacade();
    const behind = new Subject<ReturnType<typeof facadeState>>();
    vi.mocked(stuck.state).mockReturnValue(behind as never);
    sdk.init.mockResolvedValue(stuck);
    const fresh = stubFacade();
    sdk.initialiseWalletFacade.mockResolvedValueOnce(fresh);

    const opening = openFundingWallet(KEYS, "undeployed", ENDPOINTS, SNAPSHOT);
    // A stuck restore still reports its state, just never further along.
    let seconds = 0;
    while (vi.mocked(fresh.start).mock.calls.length === 0 && seconds < 600) {
      behind.next(facadeState(false));
      await vi.advanceTimersByTimeAsync(1_000);
      seconds += 1;
    }
    await opening;

    expect(fresh.start).toHaveBeenCalledOnce();
    // Every stalled interval counts, restarts included: three minutes and one check.
    expect(seconds).toBeGreaterThanOrEqual(180);
    expect(seconds).toBeLessThan(195);
    // Restarted on every stalled interval, and stopped each time.
    expect(sdk.init.mock.calls.length).toBeGreaterThan(2);
    expect(vi.mocked(stuck.stop).mock.calls.length).toBe(sdk.init.mock.calls.length);
  });

  it("waits out an indexer outage, then restarts a stalled restore instead of a full sync", async () => {
    vi.useFakeTimers();
    let indexerUp = false;
    stubIndexer(() => indexerUp);
    const stalled = stubFacade();
    const behind = new Subject<ReturnType<typeof facadeState>>();
    vi.mocked(stalled.state).mockReturnValue(behind as never);
    const reconnected = stubFacade(new Subject(), true);
    sdk.init.mockResolvedValueOnce(stalled).mockResolvedValueOnce(reconnected);

    let opened = false;
    const opening = openFundingWallet(KEYS, "undeployed", ENDPOINTS, SNAPSHOT).then((wallet) => {
      opened = true;
      return wallet;
    });
    // Ten minutes of outage: far past the fallback, which only an answering indexer counts.
    for (let second = 0; second < 600; second += 1) {
      behind.next(facadeState(false));
      await vi.advanceTimersByTimeAsync(1_000);
    }
    expect(stalled.stop).not.toHaveBeenCalled();
    expect(sdk.init).toHaveBeenCalledOnce();

    indexerUp = true;
    let seconds = 0;
    while (!opened && seconds < 60) {
      behind.next(facadeState(false));
      await vi.advanceTimersByTimeAsync(1_000);
      seconds += 1;
    }
    await opening;

    // Within one check interval and the probe of the indexer answering again.
    expect(seconds).toBeLessThanOrEqual(12);
    expect(stalled.stop).toHaveBeenCalledOnce();
    expect(sdk.init).toHaveBeenCalledTimes(2);
    // Resumed from where the stalled restore got to, not from the snapshot again.
    const resumed = sdk.init.mock.calls[1]![0];
    expect(resumed.shielded({})).toMatchObject({ kind: "shielded", state: "shielded-state" });
    expect(resumed.unshielded({})).toMatchObject({ kind: "unshielded", state: "unshielded-state" });
    expect(resumed.dust({})).toMatchObject({ kind: "dust", state: "dust-state" });
    expect(sdk.initialiseWalletFacade).not.toHaveBeenCalled();
    expect(reconnected.stop).not.toHaveBeenCalled();
  });

  it("leaves a restore alone while it keeps making progress, however long it takes", async () => {
    vi.useFakeTimers();
    stubIndexer(() => true);
    const slow = stubFacade();
    const progress = new Subject<ReturnType<typeof facadeState>>();
    vi.mocked(slow.state).mockReturnValue(progress as never);
    sdk.init.mockResolvedValueOnce(slow);

    const opening = openFundingWallet(KEYS, "undeployed", ENDPOINTS, SNAPSHOT);
    // Five minutes of replay, one dust event a second, then caught up.
    for (let second = 0; second < 300; second += 1) {
      progress.next(behindAt(second));
      await vi.advanceTimersByTimeAsync(1_000);
    }
    progress.next(facadeState(true));
    await vi.advanceTimersByTimeAsync(1_000);
    await opening;

    expect(sdk.init).toHaveBeenCalledOnce();
    expect(slow.stop).not.toHaveBeenCalled();
    expect(sdk.initialiseWalletFacade).not.toHaveBeenCalled();
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

describe("ensureCurrent", () => {
  const dustAt = (appliedIndex: bigint) => ({
    progress: { appliedIndex, isStrictlyComplete: () => true },
  });

  // A synced wallet whose DUST sub-wallet has applied events up to `applied`.
  async function openAt(applied: bigint) {
    const dust = new BehaviorSubject<ReturnType<typeof dustAt>>(dustAt(applied));
    const stale = stubFacade(dust as never, true);
    sdk.initialiseWalletFacade.mockResolvedValueOnce(stale);
    const wallet = await openFundingWallet(KEYS, "undeployed", ENDPOINTS);
    return { wallet, stale, dust };
  }

  it("asks the indexer from the wallet's applied event and leaves a current wallet alone", async () => {
    const { wallet } = await openAt(5n);
    probe.latestDustEventId.mockResolvedValueOnce(5n);

    await wallet.ensureCurrent(60_000);

    expect(probe.latestDustEventId).toHaveBeenCalledExactlyOnceWith(
      ENDPOINTS.indexerWsUrl,
      5n,
      expect.any(Number),
    );
    expect(sdk.init).not.toHaveBeenCalled();
  });

  it("submits as before when the indexer does not answer the probe", async () => {
    const { wallet } = await openAt(5n);
    probe.latestDustEventId.mockResolvedValueOnce(undefined);

    await wallet.ensureCurrent(60_000);

    expect(sdk.init).not.toHaveBeenCalled();
  });

  it("gives the wallet's own sockets a few seconds to apply what the probe saw", async () => {
    vi.useFakeTimers();
    const { wallet, dust } = await openAt(5n);
    probe.latestDustEventId.mockResolvedValueOnce(7n);

    const checked = wallet.ensureCurrent(60_000);
    await vi.advanceTimersByTimeAsync(1_000);
    dust.next(dustAt(7n));
    await checked;

    expect(sdk.init).not.toHaveBeenCalled();
  });

  it("resyncs a wallet behind the indexer from its own state, and spends with the new facade", async () => {
    vi.useFakeTimers();
    const { wallet, stale } = await openAt(5n);
    // One event behind is behind.
    probe.latestDustEventId.mockResolvedValueOnce(6n);
    const fresh = stubFacade(new BehaviorSubject(dustAt(7n)) as never, true);
    sdk.init.mockResolvedValueOnce(fresh);

    const checked = wallet.ensureCurrent(60_000);
    await vi.advanceTimersByTimeAsync(5_000);
    await checked;

    const resumed = sdk.init.mock.calls[0]![0];
    expect(resumed.shielded({})).toMatchObject({ kind: "shielded", state: "shielded-state" });
    expect(resumed.unshielded({})).toMatchObject({ kind: "unshielded", state: "unshielded-state" });
    expect(resumed.dust({})).toMatchObject({ kind: "dust", state: "dust-state" });
    expect(stale.stop).toHaveBeenCalledOnce();
    expect(fresh.stop).not.toHaveBeenCalled();
    await wallet.submitTx(stubTx());
    expect(fresh.submitTransaction).toHaveBeenCalledOnce();
    expect(stale.submitTransaction).not.toHaveBeenCalled();
  });

  it("refuses wallet_unsynced while a resync runs over budget, and the next check waits for it", async () => {
    vi.useFakeTimers();
    const { wallet, stale } = await openAt(5n);
    probe.latestDustEventId.mockResolvedValueOnce(7n);
    const fresh = stubFacade(new BehaviorSubject(dustAt(7n)) as never, true);
    let restored!: (facade: WalletFacade) => void;
    sdk.init.mockReturnValueOnce(new Promise((resolve) => (restored = resolve)));

    const first = wallet.ensureCurrent(10_000).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(15_000);
    const refusal = await first;
    expect(refusal).toBeInstanceOf(PublisherError);
    expect(refusal).toMatchObject({ code: "wallet_unsynced" });
    // Still the stale facade, which keeps running until its replacement has synced.
    expect(stale.stop).not.toHaveBeenCalled();
    await expect(wallet.snapshot()).rejects.toMatchObject({ code: "wallet_busy" });

    const second = wallet.ensureCurrent(60_000);
    restored(fresh);
    await vi.advanceTimersByTimeAsync(1_000);
    await second;

    expect(sdk.init).toHaveBeenCalledOnce();
    expect(probe.latestDustEventId).toHaveBeenCalledOnce();
    expect(stale.stop).toHaveBeenCalledOnce();
  });

  it("waits at most a minute for a resync, whatever the submit has left", async () => {
    vi.useFakeTimers();
    const { wallet } = await openAt(5n);
    probe.latestDustEventId.mockResolvedValueOnce(7n);
    sdk.init.mockReturnValueOnce(new Promise(() => undefined));
    let refusal: unknown;
    void wallet.ensureCurrent(300_000).catch((error: unknown) => (refusal = error));

    await vi.advanceTimersByTimeAsync(5_000 + 59_000);
    expect(refusal).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(refusal).toMatchObject({ code: "wallet_unsynced" });
  });

  it("keeps the stale facade when the resync fails, and checks again next time", async () => {
    vi.useFakeTimers();
    const { wallet, stale } = await openAt(5n);
    probe.latestDustEventId.mockResolvedValue(7n);
    sdk.init.mockRejectedValueOnce(new Error("indexer gone"));

    const first = wallet.ensureCurrent(60_000);
    await vi.advanceTimersByTimeAsync(5_000);
    await first;
    expect(stale.stop).not.toHaveBeenCalled();
    await wallet.submitTx(stubTx());
    expect(stale.submitTransaction).toHaveBeenCalledOnce();

    const fresh = stubFacade(new BehaviorSubject(dustAt(7n)) as never, true);
    sdk.init.mockResolvedValueOnce(fresh);
    const second = wallet.ensureCurrent(60_000);
    await vi.advanceTimersByTimeAsync(5_000);
    await second;
    expect(probe.latestDustEventId).toHaveBeenCalledTimes(2);
    expect(stale.stop).toHaveBeenCalledOnce();
  });
});
