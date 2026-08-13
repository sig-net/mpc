import { rmSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const fixtureDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(fixtureDir, "../..");
const managedDir = resolve(fixtureDir, "managed");
const compile = spawnSync(
  "compact",
  ["compile", "--feature-zkir-v3", "caller.compact", "managed/caller"],
  {
    cwd: fixtureDir,
    env: { ...process.env, COMPACT_PATH: resolve(packageDir, "node_modules") },
    stdio: "inherit",
  },
);
if (compile.error !== undefined) throw compile.error;
if (compile.status !== 0) process.exit(compile.status ?? 1);

const signerLink = resolve(managedDir, "SignetSigner");
rmSync(signerLink, { recursive: true, force: true });
symlinkSync(
  resolve(packageDir, "node_modules/@sig-net/midnight-contract/dist/managed"),
  signerLink,
  "dir",
);
