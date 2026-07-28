// Provenance for midnight-epsilon.json. Every value in that file is whatever
// this script prints, taken from `@sig-net/midnight`, the implementation
// integrators derive their keys with. Nothing here may call the Rust code the
// golden tests.
//
//   npm i @sig-net/midnight && node midnight-epsilon.mjs > midnight-epsilon.json
//
// Re-run it only to adopt a deliberate upstream change. A failing golden means
// the two implementations disagree; never re-freeze one to make a test pass.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import {
  deriveEpsilon,
  EPSILON_DERIVATION_PREFIX,
  MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH,
  MIDNIGHT_TESTNET_CHAIN_ID,
} from "@sig-net/midnight";

// The package does not export ./package.json, so walk up from its entry point.
let dir = dirname(createRequire(import.meta.url).resolve("@sig-net/midnight"));
while (!dir.endsWith("@sig-net/midnight")) dir = dirname(dir);
const { version } = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));

const CONTRACT = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

// A plain path, the response-key path, the empty path, and a path carrying the
// separator the derivation string is built from.
const CASES = [
  [CONTRACT, "vault"],
  [CONTRACT, MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH],
  [CONTRACT, ""],
  ["0".repeat(64), "a:b:c"],
];

console.log(
  JSON.stringify(
    {
      provenance: {
        package: `@sig-net/midnight@${version}`,
        source: "src/epsilon-derivation.ts",
        function: "deriveEpsilon(requester, path, chainId = MIDNIGHT_TESTNET_CHAIN_ID)",
        generator: "signet-crypto/fixtures/midnight-epsilon.mjs",
      },
      constants: {
        epsilon_derivation_prefix: EPSILON_DERIVATION_PREFIX,
        midnight_chain_id: MIDNIGHT_TESTNET_CHAIN_ID,
        respond_bidirectional_path: MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH,
      },
      vectors: CASES.map(([requester, path]) => ({
        requester,
        path,
        epsilon: deriveEpsilon(requester, path).toString(16).padStart(64, "0"),
      })),
    },
    null,
    2,
  ),
);
