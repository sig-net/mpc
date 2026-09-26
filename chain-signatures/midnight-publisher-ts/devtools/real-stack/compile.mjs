import { rmSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

// Usage: node compile.mjs <contract>, compiling <contract>.compact into managed/<contract>.
const [contract] = process.argv.slice(2);
if (contract === undefined) throw new Error("usage: compile.mjs <contract>");
const fixtureDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(fixtureDir, "../..");
const managedDir = resolve(fixtureDir, "managed");
const compile = spawnSync(
  "compact",
  ["compile", "--feature-zkir-v3", `${contract}.compact`, `managed/${contract}`],
  {
    cwd: fixtureDir,
    env: { ...process.env, COMPACT_PATH: resolve(packageDir, "node_modules") },
    stdio: "inherit",
  },
);
if (compile.error !== undefined) throw compile.error;
if (compile.status !== 0) process.exit(compile.status ?? 1);

// Generated code imports the Signet singleton it calls from this sibling directory.
const signerLink = resolve(managedDir, "SignetSigner");
rmSync(signerLink, { recursive: true, force: true });
symlinkSync(
  resolve(packageDir, "node_modules/@sig-net/midnight-contract/dist/managed"),
  signerLink,
  "dir",
);
