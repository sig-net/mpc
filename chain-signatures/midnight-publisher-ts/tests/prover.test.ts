// What the proof server is handed, and what it is not. The key locations below arrive
// inside caller-supplied intent bytes and are about to become paths, so this file is
// mostly about what never becomes one.
//
// Nothing here reaches a proof server: every case is decided before the first request.

import { describe, expect, it } from "vitest";

import { provingProvider } from "../src/prover.js";
import { managedDir } from "./support.js";

// Never dialled: every case below fails on the key location first.
const NOWHERE = "http://127.0.0.1:1";

const provider = () => provingProvider(managedDir(), NOWHERE);

describe("the proving provider", () => {
  it("carries the compiled contract's own key material for a circuit it has", async () => {
    // The whole reason this module exists: the proof server holds the protocol's keys
    // and not the contract's, and answers `bad input` for a call it cannot resolve.
    const material = await provider().lookupKey("respond");

    expect(material?.proverKey.length).toBeGreaterThan(0);
    expect(material?.verifierKey.length).toBeGreaterThan(0);
    expect(material?.ir.length).toBeGreaterThan(0);
  });

  it("leaves the protocol's own circuits to the server", async () => {
    // Zswap and dust key locations belong to the proof server. Supplying local material
    // for one would be answering a question that was not asked.
    for (const builtin of ["midnight/zswap/spend", "midnight/zswap/output", "midnight/dust/spend"]) {
      expect(await provider().lookupKey(builtin), builtin).toBeUndefined();
    }
  });

  it("refuses a key location that is not a circuit name, before it becomes a path", async () => {
    // The key location is read out of bytes this process did not write. Anything with a
    // separator or a dot in it is not a `compactc` artifact name, and accepting one
    // would let the wire choose which file gets read off the operator's disk.
    const hostile = ["../../../../etc/passwd", "keys/respond", "respond/../../secret", ".env", "/etc/passwd", ""];

    for (const keyLocation of hostile) {
      await expect(provider().lookupKey(keyLocation), keyLocation).rejects.toMatchObject({ code: "bad_request" });
    }
  });

  it("names the managed dir when a well-formed circuit name has no artifacts", async () => {
    // A managed dir built for a different contract than the caller ran the circuit
    // against. Same remedy as an absent entry point, one step later.
    await expect(provider().lookupKey("notACircuit")).rejects.toMatchObject({ code: "contract_mismatch" });
    await expect(provider().lookupKey("notACircuit")).rejects.toThrowError(/MIDNIGHT_PUB_MANAGED_DIR/);
  });
});
