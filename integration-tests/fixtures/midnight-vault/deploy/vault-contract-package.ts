import { fileURLToPath } from "node:url";

/** Absolute path of the fixture contract sources and compiled managed output. */
export const VAULT_CONTRACT_ENTRY_DIR = fileURLToPath(new URL("../contract/src/", import.meta.url));
