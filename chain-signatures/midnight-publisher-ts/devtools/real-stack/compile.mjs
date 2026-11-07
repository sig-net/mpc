import { existsSync, rmSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import console from "node:console";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

// Usage: node compile.mjs <contract>, compiling <contract>.compact into managed/<contract>.
const [contract] = process.argv.slice(2);
if (contract === undefined) throw new Error("usage: compile.mjs <contract>");
const fixtureDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(fixtureDir, "../..");
const managedDir = resolve(fixtureDir, "managed");

const compactPath = resolve(packageDir, "node_modules");

// CI restores managed/<contract> from a cache keyed on every input of this compile (see
// test-chain-midnight.yml); compactc's output, keys included, is a pure function of them.
const restored =
  process.env.REAL_STACK_CONTRACTS_RESTORED === "true" &&
  existsSync(resolve(managedDir, contract, "keys"));
if (restored) {
  console.log(`using the restored managed/${contract}`);
} else {
  const compile = spawnSync(
    "compact",
    ["compile", "--feature-zkir-v3", `${contract}.compact`, `managed/${contract}`],
    {
      cwd: fixtureDir,
      env: { ...process.env, COMPACT_PATH: compactPath },
      stdio: "inherit",
    },
  );
  if (compile.error !== undefined) throw compile.error;
  if (compile.status !== 0) process.exit(compile.status ?? 1);
}

// Generated code imports the Signet singleton it calls from this sibling directory.
const signerLink = resolve(managedDir, "SignetSigner");
rmSync(signerLink, { recursive: true, force: true });
symlinkSync(
  resolve(packageDir, "node_modules/@sig-net/midnight-contract/dist/managed"),
  signerLink,
  "dir",
);
