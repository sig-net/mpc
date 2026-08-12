import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { CostModel, createProvingPayload, Transaction } from "@midnightntwrk/ledger-v9";
import { describe, expect, it } from "vitest";

import { buildIntent } from "../src/intent.js";
import { provingProvider } from "../src/prover.js";
import { decodeIntent } from "../src/submit.js";
import { managedDir, respondInput } from "./support.js";

const NOWHERE = "http://127.0.0.1:1";

const provider = () => provingProvider(managedDir(), NOWHERE);

async function proofRequest() {
  const intent = await buildIntent(managedDir(), await respondInput());
  const transaction = Transaction.fromParts("undeployed", undefined, undefined, decodeIntent(intent));
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

async function serve(handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>) {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => {
      server.closeAllConnections();
      return new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    },
  };
}

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

  it("posts ledger payloads and reports proof-server status failures", async () => {
    let body = new Uint8Array();
    let contentType: string | undefined;
    const server = await serve(async (request, response) => {
      if (request.url === "/check") {
        response.writeHead(503).end("warming up");
        return;
      }
      contentType = request.headers["content-type"];
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      body = Buffer.concat(chunks);
      response.writeHead(200).end(Buffer.from([7, 8, 9]));
    });
    const live = provingProvider(managedDir(), server.url);
    try {
      const request = await proofRequest();
      await expect(live.check(request.preimage, request.keyLocation)).rejects.toThrow(
        "proof server answered 503 to /check: warming up",
      );
      await expect(live.prove(request.preimage, request.keyLocation, 4n)).resolves.toEqual(Uint8Array.of(7, 8, 9));
      expect(contentType).toBe("application/octet-stream");
      expect(Uint8Array.from(body)).toEqual(
        createProvingPayload(request.preimage, 4n, await live.lookupKey(request.keyLocation)),
      );
    } finally {
      await server.close();
    }
  });
});
