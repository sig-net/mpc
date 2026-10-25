import { describe, expect, it } from "vitest";

import { decodeSnapshot, encodeSnapshot } from "../src/snapshot.js";

const STATES = { shielded: "s", unshielded: "u", dust: "d" };
const TAKEN_AT = new Date("2026-10-19T09:00:00Z");

describe("wallet snapshot envelope", () => {
  it("round-trips the states and when they were taken, for the same wallet on the same network", () => {
    expect(
      decodeSnapshot(encodeSnapshot("preview", "owner", STATES, TAKEN_AT), "preview", "owner"),
    ).toEqual({ states: STATES, takenAt: TAKEN_AT });
  });

  it("rejects another network, another wallet, another version, or garbage", () => {
    const encoded = encodeSnapshot("preview", "owner", STATES, TAKEN_AT);
    expect(decodeSnapshot(encoded, "preprod", "owner")).toEqual({
      rejected: "taken on network preview",
    });
    expect(decodeSnapshot(encoded, "preview", "other")).toEqual({
      rejected: "taken for another funding wallet",
    });
    for (const garbage of ["", "{", "[]", JSON.stringify({ ...JSON.parse(encoded), version: 2 })]) {
      expect(decodeSnapshot(garbage, "preview", "owner"), garbage).toHaveProperty("rejected");
    }
  });
});
