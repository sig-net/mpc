import { mkdirSync, rmSync, symlinkSync } from "node:fs";
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

// The package each contract's `import "@sig-net/midnight/src/Signet"` resolves to. The
// vendored vault is written against @sig-net/midnight 0.24.0-rc.10, installed under the
// @sig-net/midnight-respond-oracle alias; the caller uses the 0.24.0-rc.4 package.
const signetLibrary = {
  "erc20-vault": "@sig-net/midnight-respond-oracle",
}[contract];
let compactPath = resolve(packageDir, "node_modules");
if (signetLibrary !== undefined) {
  compactPath = resolve(managedDir, `compact-path-${contract}`);
  rmSync(compactPath, { recursive: true, force: true });
  mkdirSync(resolve(compactPath, "@sig-net"), { recursive: true });
  symlinkSync(
    resolve(packageDir, "node_modules", signetLibrary),
    resolve(compactPath, "@sig-net/midnight"),
    "dir",
  );
}

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

// Generated code imports the Signet singleton it calls from this sibling directory.
const signerLink = resolve(managedDir, "SignetSigner");
rmSync(signerLink, { recursive: true, force: true });
symlinkSync(
  resolve(packageDir, "node_modules/@sig-net/midnight-contract/dist/managed"),
  signerLink,
  "dir",
);
