// Nothing here reaches a proof server: every case is decided before the first request.

import { describe, expect, it } from "vitest";

import { provingProvider } from "../src/prover.js";
import { managedDir } from "./support.js";

const NOWHERE = "http://127.0.0.1:1";

const provider = () => provingProvider(managedDir(), NOWHERE);

describe("the proving provider", () => {
  it("carries the compiled contract's own key material for a circuit it has", async () => {
    const material = await provider().lookupKey("respond");

    expect(material?.proverKey.length).toBeGreaterThan(0);
    expect(material?.verifierKey.length).toBeGreaterThan(0);
    expect(material?.ir.length).toBeGreaterThan(0);
  });

  it("leaves the protocol's own circuits to the server", async () => {
    for (const builtin of ["midnight/zswap/spend", "midnight/zswap/output", "midnight/dust/spend"]) {
      expect(await provider().lookupKey(builtin), builtin).toBeUndefined();
    }
  });

  it("refuses a key location that is not a circuit name, before it becomes a path", async () => {
    // The key location is read out of bytes this process did not write.
    const hostile = ["../../../../etc/passwd", "keys/respond", "respond/../../secret", ".env", "/etc/passwd", ""];

    for (const keyLocation of hostile) {
      await expect(provider().lookupKey(keyLocation), keyLocation).rejects.toMatchObject({ code: "bad_request" });
    }
  });

  it("names the managed dir when a well-formed circuit name has no artifacts", async () => {
    await expect(provider().lookupKey("notACircuit")).rejects.toMatchObject({ code: "contract_mismatch" });
    await expect(provider().lookupKey("notACircuit")).rejects.toThrowError(/MIDNIGHT_PUB_MANAGED_DIR/);
  });
});
