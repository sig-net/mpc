import { encodeContractKeyLocation } from "@midnight-ntwrk/compact-js";
import {
  CostModel,
  createProvingPayload,
  Transaction,
  type ProvingProvider,
  type UnprovenTransaction,
} from "@midnightntwrk/ledger-v9";
import { expectedVk, type SignetContractCircuitId } from "@sig-net/midnight-contract";
import { afterEach, describe, expect, it, vi } from "vitest";

import { buildIntent } from "../src/intent.js";
import { proveTransaction, provingProvider, type UnboundTransaction } from "../src/prover.js";
import { decodeIntent } from "../src/submit.js";
import { respondInput, SINGLETON } from "./support.js";

const NOWHERE = "http://127.0.0.1:1";

const provider = () => provingProvider(NOWHERE, new AbortController().signal);

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function fakeTransaction(
  prove: (provider: ProvingProvider) => Promise<UnboundTransaction>,
): UnprovenTransaction {
  return { prove } as unknown as UnprovenTransaction;
}

const contractKeyLocation = (
  circuit: SignetContractCircuitId,
  verifierKeyHash = expectedVk[circuit]!,
) => encodeContractKeyLocation({ contractAddress: SINGLETON, circuitId: circuit, verifierKeyHash });

async function unprovenTransaction(circuit: "respond" | "respondBidirectional" = "respond") {
  const intent = await buildIntent(await respondInput({ circuit }));
  return Transaction.fromParts("undeployed", undefined, undefined, decodeIntent(intent));
}

async function proofRequest(circuit: "respond" | "respondBidirectional" = "respond") {
  const transaction = await unprovenTransaction(circuit);
  let captured: { preimage: Uint8Array; keyLocation: string } | undefined;
  const stop = new Error("captured proof request");
  await transaction
    .prove(
      {
        check: async (preimage, keyLocation) => {
          captured = { preimage, keyLocation };
          throw stop;
        },
        prove: async (preimage, keyLocation) => {
          captured = { preimage, keyLocation };
          throw stop;
        },
        lookupKey: async () => undefined,
      },
      CostModel.initialCostModel(),
    )
    .catch((error) => {
      if (captured === undefined) throw error;
    });
  if (captured === undefined) throw new Error("transaction requested no proof");
  return captured;
}

describe("the proving provider", () => {
  it("carries the compiled contract's key material for its supported circuits", async () => {
    for (const circuit of ["respond", "respondBidirectional"] as const) {
      const material = await provider().lookupKey(contractKeyLocation(circuit));

      expect(material?.proverKey.length, circuit).toBeGreaterThan(0);
      expect(material?.verifierKey.length, circuit).toBeGreaterThan(0);
      expect(material?.ir.length, circuit).toBeGreaterThan(0);
    }
  });

  it("puts the contract address, circuit, and verifier hash in proof requests", async () => {
    for (const circuit of ["respond", "respondBidirectional"] as const) {
      await expect(proofRequest(circuit)).resolves.toMatchObject({
        keyLocation: contractKeyLocation(circuit),
      });
    }
  });

  it("leaves the protocol's own circuits to the server", async () => {
    expect(await provider().lookupKey("midnight/zswap/spend")).toBeUndefined();
  });

  it("refuses locations outside the publisher's exact contract surface", async () => {
    for (const keyLocation of [
      "respond",
      "notACircuit",
      "../../../../etc/passwd",
      contractKeyLocation("signBidirectional"),
    ]) {
      await expect(provider().lookupKey(keyLocation), keyLocation).rejects.toMatchObject({
        code: "bad_request",
      });
      await expect(provider().lookupKey(keyLocation), keyLocation).rejects.toThrowError(
        /unsupported key location/,
      );
    }
  });

  it("refuses a canonical location for different verifier material", async () => {
    await expect(
      provider().lookupKey(contractKeyLocation("respond", "00".repeat(32))),
    ).rejects.toMatchObject({
      code: "bad_request",
    });
  });

  it("posts ledger payloads and reports proof-server status failures", async () => {
    let body = new Uint8Array();
    let contentType: string | undefined;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      if (new URL(String(input)).pathname === "/check") {
        return new Response("warming up", { status: 503 });
      }
      contentType = new Headers(init?.headers).get("content-type") ?? undefined;
      body = Uint8Array.from(init?.body as Uint8Array);
      return new Response(Uint8Array.of(7, 8, 9), { status: 200 });
    });
    const live = provingProvider("http://proof.invalid", new AbortController().signal);
    const request = await proofRequest();
    await expect(live.check(request.preimage, request.keyLocation)).rejects.toThrow(
      "proof server answered 503 to /check: warming up",
    );
    await expect(live.prove(request.preimage, request.keyLocation, 4n)).resolves.toEqual(
      Uint8Array.of(7, 8, 9),
    );
    expect(contentType).toBe("application/octet-stream");
    expect(Uint8Array.from(body)).toEqual(
      createProvingPayload(request.preimage, 4n, await live.lookupKey(request.keyLocation)),
    );
  });

  it("passes one owned signal through every check and prove request", async () => {
    vi.useFakeTimers();
    const signals: (AbortSignal | null | undefined)[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      signals.push(init?.signal);
      return new Response(Uint8Array.of(7, 8, 9), { status: 200 });
    });
    const request = await proofRequest();
    const transaction = fakeTransaction(async (live) => {
      await live.check(request.preimage, request.keyLocation).catch(() => undefined);
      await live.prove(request.preimage, request.keyLocation, 4n);
      return { proven: true } as unknown as UnboundTransaction;
    });

    await proveTransaction("http://proof.invalid", transaction, 1_000);

    expect(signals).toHaveLength(2);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
    expect(signals[1]).toBe(signals[0]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("enforces the aggregate proving budget when proof work ignores the provider and resolves late", async () => {
    vi.useFakeTimers();
    const lateResult = { proven: "too late" } as unknown as UnboundTransaction;
    let underlyingResolved = false;
    const transaction = fakeTransaction(
      () =>
        new Promise<UnboundTransaction>((resolve) => {
          setTimeout(() => {
            underlyingResolved = true;
            resolve(lateResult);
          }, 121);
        }),
    );
    let observed: { readonly result?: UnboundTransaction; readonly error?: unknown } | undefined;
    const proving = proveTransaction("http://proof.invalid", transaction, 20).then(
      (result) => (observed = { result }),
      (error: unknown) => (observed = { error }),
    );

    await vi.advanceTimersByTimeAsync(19);
    expect(observed).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    const outcomeAtBudget = observed;
    await vi.advanceTimersByTimeAsync(101);
    await proving;

    expect(outcomeAtBudget).toMatchObject({
      error: {
        code: "proving_timeout",
        message: expect.stringMatching(/no wallet operation started.*retry is safe/i),
      },
    });
    expect(underlyingResolved).toBe(true);
    expect(observed).toBe(outcomeAtBudget);
    expect(observed).not.toMatchObject({ result: lateResult });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("aborts active proof I/O with the owned timeout", async () => {
    vi.useFakeTimers();
    const request = await proofRequest();
    let signal: AbortSignal | undefined;
    let entered!: () => void;
    const requestEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      signal = init?.signal ?? undefined;
      entered();
      return new Promise<Response>(() => undefined);
    });
    const transaction = fakeTransaction(async (live) => {
      await live.check(request.preimage, request.keyLocation);
      throw new Error("proof request unexpectedly completed");
    });
    const proving = proveTransaction("http://proof.invalid", transaction, 25).then(
      () => new Error("proving unexpectedly succeeded"),
      (error: unknown) => error,
    );

    await requestEntered;
    await vi.advanceTimersByTimeAsync(25);
    const error = await proving;

    expect(error).toMatchObject({ code: "proving_timeout" });
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(signal?.aborted).toBe(true);
    expect(signal?.reason).toBe(error);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not classify arbitrary abort-like or network failures as proving timeouts", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.spyOn(globalThis, "fetch");
    for (const foreign of [
      new DOMException("caller cancelled", "AbortError"),
      new DOMException("foreign timeout", "TimeoutError"),
      new Error("connection reset"),
    ]) {
      const request = await proofRequest();
      fetchMock.mockReset();
      fetchMock.mockRejectedValue(foreign);
      const transaction = fakeTransaction(async (live) => {
        await live.prove(request.preimage, request.keyLocation, 4n);
        throw new Error("proof request unexpectedly completed");
      });

      await expect(proveTransaction("http://proof.invalid", transaction, 1_000)).rejects.toBe(
        foreign,
      );
      expect(vi.getTimerCount()).toBe(0);
    }
  });
});
