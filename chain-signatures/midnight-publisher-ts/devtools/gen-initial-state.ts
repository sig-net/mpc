import { writeFileSync } from "node:fs";
import { initialSingletonStateHex } from "../tests/support.js";

// Writes the synthesized initial singleton state as raw bytes. The committed
// copy is the cross-language fixture the Rust differential test will read via
// include_bytes!; the vitest guard in protocol.test.ts keeps it honest.
const hex = await initialSingletonStateHex();
writeFileSync(new URL("../tests/fixtures/initial-singleton-state.mn", import.meta.url), Buffer.from(hex, "hex"));
console.log(`wrote initial-singleton-state.mn (${hex.length / 2} bytes)`);
