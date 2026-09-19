import { mkdirSync, rmSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const fixtureDir = dirname(fileURLToPath(import.meta.url));
const managedDir = resolve(fixtureDir, "contract/src/managed");
const compile = spawnSync(
  "compact",
  [
    "compile",
    "+0.33.0-rc.2",
    "--feature-zkir-v3",
    "contract/src/erc20-vault.compact",
    "contract/src/managed/erc20-vault",
  ],
  {
    cwd: fixtureDir,
    env: { ...process.env, COMPACT_PATH: resolve(fixtureDir, "node_modules") },
    stdio: "inherit",
  },
);
if (compile.error !== undefined) throw compile.error;
if (compile.status !== 0) process.exit(compile.status ?? 1);
mkdirSync(managedDir, { recursive: true });
const signerLink = resolve(managedDir, "SignetSigner");
rmSync(signerLink, { recursive: true, force: true });
symlinkSync("../../../node_modules/@sig-net/midnight-contract/dist/managed", signerLink, "dir");
